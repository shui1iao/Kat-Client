package kernel

// TrafficTotals reads the same process-wide atomic cumulative counters used by
// StatsView, without building provider, rule or group snapshots.
func (s *Server) TrafficTotals() (up, down uint64) {
	t := s.core.reg.Total.Load()
	return t.Up, t.Down
}

// GenerationID reads the current generation at this call, including when s is
// an older Server handle. It does not cache a generation across status requests.
func (s *Server) GenerationID() uint64 {
	if g := s.core.gen.Load(); g != nil {
		return g.id
	}
	return 0
}
