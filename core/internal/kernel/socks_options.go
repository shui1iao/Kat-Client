package kernel

// SOCKS5Options contains only the client's local UDP fragment policy.
type SOCKS5Options struct {
	UDPFragment *UDPFragmentOptions `json:"udp_fragment,omitempty"`
}
type UDPFragmentOptions struct {
	Disabled bool     `json:"disabled,omitempty"`
	MaxBytes int      `json:"max_bytes,omitempty"`
	Timeout  Duration `json:"timeout,omitempty"`
}

func (in *Inbound) fragmentOptions() *UDPFragmentOptions {
	if in.SOCKS5 != nil && in.SOCKS5.UDPFragment != nil {
		if in.SOCKS5.UDPFragment.Disabled {
			return nil
		}
		return in.SOCKS5.UDPFragment
	}
	return &UDPFragmentOptions{MaxBytes: defaultFragmentAssoc, Timeout: Duration(defaultFragmentTimeout)}
}
