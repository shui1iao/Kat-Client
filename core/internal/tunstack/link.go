// Zero-copy batched TUN packet pump for Kat's pure-Go System Stack.
package tunstack

import (
	"errors"
)

const (
	tunReadBatchSize = 16
	tunBatchSlotSize = 65536
)

type wintunRingFullError interface {
	error
	WintunRingFull() bool
}

func isWintunRingFull(err error) bool {
	var target wintunRingFullError
	return errors.As(err, &target) && target.WintunRingFull()
}

func (r *Runtime) writeRawPacket(pkt []byte) {
	r.writeMu.Lock()
	err := r.cfg.Device.WritePacket(pkt)
	r.writeMu.Unlock()
	if err != nil {
		if isWintunRingFull(err) {
			r.dropped.Add(1)
			return
		}
		r.fatal("TUN_DEVICE_WRITE_FAILED", err)
	}
}

func (r *Runtime) writeRawBatch(bw PacketBatchWriter, pkts [][]byte) bool {
	off := 0
	for off < len(pkts) {
		r.writeMu.Lock()
		written, err := bw.WritePackets(pkts[off:])
		r.writeMu.Unlock()
		if err == nil {
			return true
		}
		if isWintunRingFull(err) {
			r.dropped.Add(1)
			off += written + 1
			continue
		}
		r.fatal("TUN_DEVICE_WRITE_FAILED", err)
		return false
	}
	return true
}

// dispatchPacket parses a raw L3 packet and either:
//   - rewrites TCP packets in-place (returning out = pkt.raw or an explicit RST)
//   - reassembles fragmented IPv4/IPv6 packets and routes UDP/ICMP directly
//
// Returning a non-nil slice asks the pump to write that frame back to the TUN device.
func (r *Runtime) dispatchPacket(raw []byte) []byte {
	pkt, frag, ok := parseIPPacket(raw)
	if !ok {
		r.dropped.Add(1)
		return nil
	}
	if frag != nil {
		if r.reasm == nil {
			r.dropped.Add(1)
			return nil
		}
		var complete bool
		pkt, complete = r.reasm.push(frag)
		if !complete {
			return nil
		}
	}

	switch pkt.proto {
	case ipProtoTCP:
		if r.tcpSys == nil {
			r.dropped.Add(1)
			return nil
		}
		rewritten, rst := r.tcpSys.handleTCPInPlace(pkt)
		if rewritten {
			return pkt.raw
		}
		return rst
	case ipProtoUDP:
		r.handleUDP(pkt)
		return nil
	case ipProtoICMPv4:
		if r.hasICMP {
			r.icmpPacket4(pkt)
		}
		return nil
	case ipProtoICMPv6:
		if r.hasICMP {
			r.icmpPacket6(pkt)
		}
		return nil
	default:
		r.dropped.Add(1)
		return nil
	}
}

func (r *Runtime) readPackets() {
	br, hasBatchRead := r.cfg.Device.(PacketBatchReader)
	bw, hasBatchWrite := r.cfg.Device.(PacketBatchWriter)

	if hasBatchRead {
		backing := make([]byte, tunReadBatchSize*tunBatchSlotSize)
		bufs := make([][]byte, tunReadBatchSize)
		for i := range bufs {
			bufs[i] = backing[i*tunBatchSlotSize : (i+1)*tunBatchSlotSize]
		}
		sizes := make([]int, tunReadBatchSize)
		outBatch := make([][]byte, 0, tunReadBatchSize)
		for {
			cnt, e := br.ReadPackets(bufs, sizes)
			if e != nil && cnt == 0 {
				r.fatal("TUN_DEVICE_READ_FAILED", e)
				return
			}
			if r.ctx.Err() != nil {
				return
			}
			outBatch = outBatch[:0]
			for i := 0; i < cnt; i++ {
				n := sizes[i]
				if n <= 0 || n > len(bufs[i]) {
					r.dropped.Add(1)
					continue
				}
				if out := r.dispatchPacket(bufs[i][:n]); len(out) > 0 {
					outBatch = append(outBatch, out)
				}
			}
			if len(outBatch) > 0 {
				if hasBatchWrite {
					if !r.writeRawBatch(bw, outBatch) {
						return
					}
				} else {
					for _, p := range outBatch {
						r.writeRawPacket(p)
						if r.ctx.Err() != nil {
							return
						}
					}
				}
			}
			if e != nil {
				r.fatal("TUN_DEVICE_READ_FAILED", e)
				return
			}
		}
	}

	scratch := make([]byte, 65535)
	for {
		n, e := r.cfg.Device.ReadPacket(scratch)
		if e != nil {
			r.fatal("TUN_DEVICE_READ_FAILED", e)
			return
		}
		if r.ctx.Err() != nil {
			return
		}
		if n <= 0 || n > len(scratch) {
			r.dropped.Add(1)
			continue
		}
		if out := r.dispatchPacket(scratch[:n]); len(out) > 0 {
			r.writeRawPacket(out)
		}
	}
}
