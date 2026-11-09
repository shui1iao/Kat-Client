package clientegress

import "testing"

func TestM2UDPBindingDomainsRemainFenced(t *testing.T) {
	s := &Switch{}
	if _, _, e := s.UDPAssociationBinding(); e == nil {
		t.Fatal("nil policy admitted UDP")
	}
	snap := EgressSnapshot{Generation: 7, Epoch: 4, Options: fixtureOptions(), Owners: []OwnerState{ownerFixture()}}
	s.installSnapshot(snap, &Policy{})
	epoch, owner, e := s.UDPAssociationBinding()
	if e != nil || epoch != 4 || owner != "14/4/2" {
		t.Fatal("physical domain", epoch, owner, e)
	}
	if _, _, e = s.UDPBinding(true); e == nil {
		t.Fatal("missing direct physical IPv6 admitted")
	}
	s.FreezeNew()
	if _, _, e = s.UDPAssociationBinding(); e == nil {
		t.Fatal("fence bypassed")
	}
	s.frozen = false
	s.current.Fail()
	if _, _, e = s.UDPAssociationBinding(); e == nil {
		t.Fatal("failed policy bypassed")
	}
}
