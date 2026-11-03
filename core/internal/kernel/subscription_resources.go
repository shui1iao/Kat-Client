package kernel

// SubscriptionResourcePaths returns immutable file references of every live
// generation, including superseded generations retained by TCP/UDP flows.
// Configuration publication and generation retirement both use gensMu; a
// released generation cannot acquire a new reference after this snapshot.
func (s *Server) SubscriptionResourcePaths() []string {
	s.gensMu.Lock()
	defer s.gensMu.Unlock()
	paths := []string{}
	for _, g := range s.gens {
		for _, set := range g.cfg.RuleSets {
			paths = append(paths, set.Path)
		}
		if g.cfg.GeoIP != nil {
			paths = append(paths, g.cfg.GeoIP.Path)
		}
		if g.cfg.ASN != nil {
			paths = append(paths, g.cfg.ASN.Path)
		}
		if g.cfg.Geosite != nil {
			paths = append(paths, g.cfg.Geosite.Path)
		}
		for _, p := range g.cfg.Providers {
			paths = append(paths, p.Path)
		}
	}
	return paths
}
