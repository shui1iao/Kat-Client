package kernel

import "time"

type KernelLogEvent struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

func (c *Config) SetKernelLogSink(sink func(KernelLogEvent)) { c.clientKernelLog = sink }
