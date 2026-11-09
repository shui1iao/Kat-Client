package procattr

// IdentityCurrent is the legacy epoch fence consumed by flow details. Native
// tuple/HTTP identities retain their existing PID, path and creation-time proof;
// no retired bridge lease can be current, even if its process still exists.
func IdentityCurrent(id Identity) bool { return id.SessionEpoch == 0 }
