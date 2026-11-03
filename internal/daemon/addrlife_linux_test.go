package daemon

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// addrMessage builds an RTM_NEWADDR message as the kernel sends it.
func addrMessage(flags uint8, index uint32, attrs map[uint16]netip.Addr) syscall.NetlinkMessage {
	data := make([]byte, unix.SizeofIfAddrmsg)
	data[2] = flags
	binary.NativeEndian.PutUint32(data[4:], index)
	for typ, a := range attrs {
		v := a.AsSlice()
		attr := make([]byte, (4+len(v)+3)&^3)
		binary.NativeEndian.PutUint16(attr[0:], uint16(4+len(v)))
		binary.NativeEndian.PutUint16(attr[2:], typ)
		copy(attr[4:], v)
		data = append(data, attr...)
	}
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWADDR}, Data: data}
}

func TestParseAddrMessages(t *testing.T) {
	fixed := netip.MustParseAddr("10.99.0.20")
	leased := netip.MustParseAddr("10.99.0.30")
	slaac := netip.MustParseAddr("2001:db8::30")
	peer := netip.MustParseAddr("192.0.2.1")
	ptp := netip.MustParseAddr("192.0.2.2")
	got := parseAddrMessages([]syscall.NetlinkMessage{
		addrMessage(unix.IFA_F_PERMANENT, 2, map[uint16]netip.Addr{unix.IFA_ADDRESS: fixed, unix.IFA_LOCAL: fixed}),
		addrMessage(0, 2, map[uint16]netip.Addr{unix.IFA_ADDRESS: leased, unix.IFA_LOCAL: leased}),
		addrMessage(0, 3, map[uint16]netip.Addr{unix.IFA_ADDRESS: slaac}),
		// A point-to-point link: IFA_ADDRESS is the peer, IFA_LOCAL ours.
		addrMessage(unix.IFA_F_PERMANENT, 4, map[uint16]netip.Addr{unix.IFA_ADDRESS: peer, unix.IFA_LOCAL: ptp}),
		{Header: syscall.NlMsghdr{Type: syscall.NLMSG_DONE}},
	})
	want := map[addrKey]addrLifetime{
		{2, fixed}:  addrFixed,
		{2, leased}: addrLeased,
		{3, slaac}:  addrLeased,
		{4, ptp}:    addrFixed,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, l := range want {
		if got[k] != l {
			t.Errorf("%v: %v, want %v", k, got[k], l)
		}
	}
}

// The kernel's own answer: the loopback address is fixed.
func TestAddressLifetimes(t *testing.T) {
	lifetimes := addressLifetimes()
	if lifetimes == nil {
		t.Skip("netlink not available")
	}
	for k, l := range lifetimes {
		if k.addr == netip.MustParseAddr("127.0.0.1") {
			if l != addrFixed {
				t.Fatalf("127.0.0.1 is %v", l)
			}
			return
		}
	}
	t.Fatalf("127.0.0.1 not among %v", lifetimes)
}
