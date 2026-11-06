package portal

import "github.com/ohmycggk/nowhere-go/morph"

// MorphKeys returns an immutable snapshot for multiuser QUIC admission.
func (s *Server) MorphKeys() []morph.Keys { _, keys, _, _ := s.snapshotUsers(); return keys }
