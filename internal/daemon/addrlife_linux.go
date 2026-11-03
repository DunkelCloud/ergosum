package daemon

import (
	"encoding/binary"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// addressLifetimes asks the kernel which addresses are fixed. One from
// DHCP or SLAAC has a finite lifetime ("dynamic" in "ip addr"); a fixed one
// is permanent (IFA_F_PERMANENT). nil if the kernel cannot be asked.
func addressLifetimes() map[addrKey]addrLifetime {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil
	}
	return parseAddrMessages(msgs)
}

// parseAddrMessages reads the addresses of RTM_NEWADDR messages: struct
// ifaddrmsg (family, prefix length, flags, scope, interface index), then
// the attributes. The local address is IFA_LOCAL where there is one (a
// point-to-point link), else IFA_ADDRESS.
func parseAddrMessages(msgs []syscall.NetlinkMessage) map[addrKey]addrLifetime {
	out := map[addrKey]addrLifetime{}
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != syscall.RTM_NEWADDR || len(m.Data) < unix.SizeofIfAddrmsg {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			continue
		}
		var addr, local netip.Addr
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.IFA_ADDRESS:
				addr, _ = netip.AddrFromSlice(a.Value)
			case unix.IFA_LOCAL:
				local, _ = netip.AddrFromSlice(a.Value)
			}
		}
		if local.IsValid() {
			addr = local
		}
		if !addr.IsValid() {
			continue
		}
		l := addrLeased
		if m.Data[2]&unix.IFA_F_PERMANENT != 0 {
			l = addrFixed
		}
		out[addrKey{int(binary.NativeEndian.Uint32(m.Data[4:8])), addr.Unmap()}] = l
	}
	return out
}
