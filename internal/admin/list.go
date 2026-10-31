package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// ListAnswer is one authority's authority list; List is nil if it serves
// none.
type ListAnswer struct {
	From string
	List *protocol.AuthorityList
}

// AuthorityLists asks every configured authority for its list. Each list
// must be for the configured trust domain.
func (c *Client) AuthorityLists(ctx context.Context) ([]ListAnswer, Reach, error) {
	replies, reach, err := c.every(ctx, protocol.PathAuthorities)
	if err != nil {
		return nil, reach, err
	}
	out := make([]ListAnswer, 0, len(replies))
	for _, r := range replies {
		switch r.status {
		case http.StatusNotFound:
			out = append(out, ListAnswer{From: r.from})
			continue
		case http.StatusOK:
		default:
			return nil, reach, fmt.Errorf("%s: %d %s", r.from, r.status, errorDetail(r.data))
		}
		var l protocol.AuthorityList
		if err := json.Unmarshal(r.data, &l); err != nil {
			return nil, reach, fmt.Errorf("%s: %w", r.from, err)
		}
		if err := l.Validate(); err != nil {
			return nil, reach, fmt.Errorf("%s: unusable answer: %w", r.from, err)
		}
		if l.TrustDomain != c.cfg.TrustDomain {
			return nil, reach, fmt.Errorf("%s serves a list for trust domain %s, the configuration names %s", r.from, l.TrustDomain, c.cfg.TrustDomain)
		}
		out = append(out, ListAnswer{From: r.from, List: &l})
	}
	return out, reach, nil
}

// AgreedList returns the list that the answering authorities serve, nil if
// none serves one. They must serve the same list with the same serial.
func AgreedList(answers []ListAnswer) (*protocol.AuthorityList, error) {
	var agreed *protocol.AuthorityList
	from := ""
	for _, a := range answers {
		switch {
		case a.List == nil:
		case agreed == nil:
			agreed, from = a.List, a.From
		case a.List.Serial != agreed.Serial || !a.List.Same(agreed):
			return nil, fmt.Errorf("%w on the authority list: %s serves serial %d, %s serial %d%s",
				ErrDisagree, from, agreed.Serial, a.From, a.List.Serial, sameNote(agreed, a.List))
		}
	}
	return agreed, nil
}

func sameNote(a, b *protocol.AuthorityList) string {
	if a.Serial == b.Serial {
		return " with other instances or URLs"
	}
	return ""
}

// Expand adds the instances that the authorities' list names and the
// configuration does not, each on the first of its URLs worth trying from
// this machine, so that a configuration needs only one authority. It
// returns the list, nil if no authority serves one, and the instances it
// added.
func (c *Client) Expand(ctx context.Context) (*protocol.AuthorityList, []Authority, error) {
	answers, _, err := c.AuthorityLists(ctx)
	if err != nil {
		return nil, nil, err
	}
	list, err := AgreedList(answers)
	if err != nil || list == nil {
		return list, nil, err
	}
	configured := map[string]bool{}
	for _, a := range c.cfg.Authorities {
		configured[a.Key] = true
	}
	paths := protocol.LocalPaths(protocol.DefaultOverlayPrefixes)
	var added []Authority
	for _, la := range list.Authorities {
		if configured[la.Key] {
			continue
		}
		i := paths.Order(la.URLs, 0, protocol.DefaultOverlayPrefixes)[0]
		added = append(added, Authority{URL: la.URLs[i], Key: la.Key})
	}
	c.cfg.Authorities = append(c.cfg.Authorities, added...)
	return list, added, nil
}
