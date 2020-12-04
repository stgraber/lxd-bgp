package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"

	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	gobgp "github.com/osrg/gobgp/pkg/server"

	"github.com/lxc/lxd/client"
	"github.com/lxc/lxd/shared"
	lxdapi "github.com/lxc/lxd/shared/api"
)

var (
	confAsn          = uint32(0)
	confPeerAddress  = ""
	confPeerAsn      = uint32(0)
	confPeerPassword = ""
	confUplinks      = []string{}
	confRouterID     = ""

	currentAdv = []advertisement{}
	syncLock   = sync.Mutex{}
)

type advertisement struct {
	nexthop net.IP
	prefix  net.IPNet
	uuid    []byte
}

func main() {
	err := run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	return
}

func run() error {
	// Argument parsing.
	if len(os.Args) < 6 {
		return fmt.Errorf("Usage: %s <uplinks> <router-id> <local ASN> <peer ASN> <peer IP> [peer password]", os.Args[0])
	}

	confUplinks = strings.Split(os.Args[1], ",")
	confRouterID = os.Args[2]

	val, err := strconv.ParseUint(os.Args[3], 10, 32)
	if err != nil {
		return err
	}
	confAsn = uint32(val)

	val, err = strconv.ParseUint(os.Args[4], 10, 32)
	if err != nil {
		return err
	}
	confPeerAsn = uint32(val)
	confPeerAddress = os.Args[5]
	if len(os.Args) == 7 {
		confPeerPassword = os.Args[6]
	}

	// Start BGP.
	s, err := runBgp()
	if err != nil {
		return err
	}

	// Connect to LXD.
	for {
		fmt.Printf("INFO: Connecting to LXD\n")
		c, err := lxd.ConnectLXDUnix("/var/snap/lxd/common/lxd/unix.socket", nil)
		if err != nil {
			fmt.Printf("WARN: Unable to connect to LXD: %v\n", err)
			time.Sleep(10 * time.Second)
			continue
		}
		fmt.Printf("INFO: Connected to LXD\n")

		// Setup event listener for all projects.
		ev, err := c.UseProject("*").GetEvents()
		if err != nil {
			fmt.Printf("WARN: Failed to access LXD event API\n")
			return err
		}

		_, err = ev.AddHandler([]string{"lifecycle"}, func(ev lxdapi.Event) {
			event := lxdapi.EventLifecycle{}
			err = json.Unmarshal(ev.Metadata, &event)
			if err != nil {
				fmt.Printf("WARN: Error unpacking event: %v\n", err)
				return
			}

			if !shared.StringInSlice(event.Action, []string{"instance-created", "instance-updated", "instance-deleted", "instance-restored", "instance-started", "instance-stopped", "instance-shutdown", "network-created", "network-updated", "network-deleted"}) {
				return
			}

			updatePrefixes(s, c)
		})
		if err != nil {
			fmt.Printf("WARN: Failed to add LXD event handler\n")
			return err
		}

		// Do an initial run to validate everything is okay.
		err = updatePrefixes(s, c)
		if err != nil {
			fmt.Printf("WARN: Failed to update the prefixes: %v\n", err)
			continue
		}

		// Wait until LXD disconnects.
		err = ev.Wait()
		if err != nil {
			fmt.Printf("WARN: Lost connection with LXD\n")
			continue
		}
	}

	return nil
}

func updatePrefixes(s *gobgp.BgpServer, c lxd.InstanceServer) error {
	// Locking.
	syncLock.Lock()
	defer syncLock.Unlock()

	// Wait 1s for the database to be updated.
	time.Sleep(time.Second)

	// Get the hostname.
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	// Build up the list of expected advertisements.
	newAdv := []advertisement{}
	for _, uplink := range confUplinks {
		// Get the uplink network.
		u, _, err := c.GetNetwork(uplink)
		if err != nil {
			fmt.Printf("WARN: skipping %q: %v\n", uplink, err)
			continue
		}

		// Iterate on downstream networks.
		nEntries := parseUsedBy(u.UsedBy, "networks")
		for nProject, networks := range nEntries {
			for _, network := range networks {
				n, _, err := c.UseProject(nProject).GetNetwork(network)
				if err != nil {
					fmt.Printf("WARN: skipping %q: %v\n", network, err)
					continue
				}

				// Check if IPv4 subnet should be exported.
				ovnV4 := n.Config["volatile.network.ipv4.address"]
				if !shared.IsTrue(n.Config["ipv4.nat"]) && n.Config["ipv4.address"] != "" && n.Config["ipv4.address"] != "none" {
					_, ipnet, err := net.ParseCIDR(n.Config["ipv4.address"])
					if err != nil {
						fmt.Printf("WARN: skipping %q: %v\n", network, err)
						continue
					}

					newAdv = append(newAdv, advertisement{nexthop: net.ParseIP(ovnV4), prefix: *ipnet})
				}

				// Check if IPv6 subnet should be exported.
				ovnV6 := n.Config["volatile.network.ipv6.address"]
				if !shared.IsTrue(n.Config["ipv6.nat"]) && n.Config["ipv6.address"] != "" && n.Config["ipv6.address"] != "none" {
					_, ipnet, err := net.ParseCIDR(n.Config["ipv6.address"])
					if err != nil {
						fmt.Printf("WARN: skipping %q: %v\n", network, err)
						continue
					}

					newAdv = append(newAdv, advertisement{nexthop: net.ParseIP(ovnV6), prefix: *ipnet})
				}

				// Get instances on the network.
				iEntries := parseUsedBy(n.UsedBy, "instances")
				for iProject, instances := range iEntries {
					for _, instance := range instances {
						i, _, err := c.UseProject(iProject).GetInstance(instance)
						if err != nil {
							fmt.Printf("WARN: skipping %q: %v\n", instance, err)
							continue
						}

						// Only announce our local instances.
						if i.Location != hostname {
							continue
						}

						// Skip any instance that's not running.
						if i.StatusCode != lxdapi.Running {
							continue
						}

						// Look for any device with external routes we should announce.
						for _, dev := range i.ExpandedDevices {
							if dev["type"] != "nic" || dev["network"] != network {
								continue
							}

							if dev["ipv4.routes.external"] != "" {
								_, ipnet, err := net.ParseCIDR(dev["ipv4.routes.external"])
								if err != nil {
									fmt.Printf("WARN: skipping %q: %v\n", instance, err)
									continue
								}

								newAdv = append(newAdv, advertisement{nexthop: net.ParseIP(ovnV4), prefix: *ipnet})
							}

							if dev["ipv6.routes.external"] != "" {
								_, ipnet, err := net.ParseCIDR(dev["ipv6.routes.external"])
								if err != nil {
									fmt.Printf("WARN: skipping %q: %v\n", instance, err)
									continue
								}

								newAdv = append(newAdv, advertisement{nexthop: net.ParseIP(ovnV6), prefix: *ipnet})
							}
						}
					}
				}
			}
		}
	}

	// Drop anything that needs dropping.
	for _, prev := range currentAdv {
		found := false
		for i, next := range newAdv {
			if prev.nexthop.String() == next.nexthop.String() && prev.prefix.String() == next.prefix.String() {
				newAdv[i].uuid = prev.uuid
				found = true
				break
			}
		}

		if !found {
			err := s.DeletePath(context.Background(), &gobgpapi.DeletePathRequest{Uuid: prev.uuid})
			if err != nil {
				fmt.Printf("WARN: Couldn't drop %q via %q: %v\n", prev.prefix.String(), prev.nexthop.String(), err)
				continue
			}
			fmt.Printf("INFO: Stopped advertising %q via %q\n", prev.prefix.String(), prev.nexthop.String())

			continue
		}
	}

	// Announce the new prefixes.
	for i, adv := range newAdv {
		// Check that we don't re-announce anything.
		if adv.uuid != nil {
			continue
		}

		uuid, err := addRoute(s, adv.prefix, adv.nexthop)
		if err != nil {
			fmt.Printf("WARN: Couldn't advertise %q via %q: %v\n", adv.prefix.String(), adv.nexthop.String(), err)
			continue
		}
		fmt.Printf("INFO: Started advertising %q via %q\n", adv.prefix.String(), adv.nexthop.String())

		newAdv[i].uuid = uuid
	}
	currentAdv = newAdv

	return nil
}

func parseUsedBy(entries []string, entryType string) map[string][]string {
	out := map[string][]string{}

	for _, e := range entries {
		// Try to parse the query part of the URL.
		u, err := url.Parse(e)
		if err != nil {
			// Skip URLs we can't parse.
			continue
		}

		// Check if the right type.
		fields := strings.Split(u.Path, "/")
		if len(fields) < 4 {
			continue
		}

		if fields[2] != entryType {
			continue
		}

		// Get the project.
		projectName := "default"
		val := u.Query().Get("project")
		if val != "" {
			projectName = val
		}

		if out[projectName] == nil {
			out[projectName] = []string{}
		}

		out[projectName] = append(out[projectName], fields[3])
	}

	return out
}

func addRoute(s *gobgp.BgpServer, subnet net.IPNet, nexthop net.IP) ([]byte, error) {
	prefixLen, _ := subnet.Mask.Size()
	prefix := subnet.IP.String()

	nlri, _ := ptypes.MarshalAny(&gobgpapi.IPAddressPrefix{
		Prefix:    prefix,
		PrefixLen: uint32(prefixLen),
	})

	aOrigin, _ := ptypes.MarshalAny(&gobgpapi.OriginAttribute{
		Origin: 0,
	})

	var uuid []byte
	if subnet.IP.To4() != nil {
		aNextHop, _ := ptypes.MarshalAny(&gobgpapi.NextHopAttribute{
			NextHop: nexthop.String(),
		})

		resp, err := s.AddPath(context.Background(), &gobgpapi.AddPathRequest{
			Path: &gobgpapi.Path{
				Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
				Nlri:   nlri,
				Pattrs: []*any.Any{aOrigin, aNextHop},
			},
		})
		if err != nil {
			return nil, err
		}

		uuid = resp.Uuid
	} else {
		family := &gobgpapi.Family{
			Afi:  gobgpapi.Family_AFI_IP6,
			Safi: gobgpapi.Family_SAFI_UNICAST,
		}

		v6Attrs, _ := ptypes.MarshalAny(&gobgpapi.MpReachNLRIAttribute{
			Family:   family,
			NextHops: []string{nexthop.String()},
			Nlris:    []*any.Any{nlri},
		})

		resp, err := s.AddPath(context.Background(), &gobgpapi.AddPathRequest{
			Path: &gobgpapi.Path{
				Family: family,
				Nlri:   nlri,
				Pattrs: []*any.Any{aOrigin, v6Attrs},
			},
		})
		if err != nil {
			return nil, err
		}

		uuid = resp.Uuid
	}

	return uuid, nil
}

func runBgp() (*gobgp.BgpServer, error) {
	// Start the server.
	s := gobgp.NewBgpServer()
	go s.Serve()

	// Main configuration.
	conf := &gobgpapi.Global{
		RouterId: confRouterID,
		As:       confAsn,
		Families: []uint32{0, 1},
	}

	err := s.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{Global: conf})
	if err != nil {
		return nil, err
	}

	// Neighbor configuration.
	n := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: confPeerAddress,
			PeerAs:          confPeerAsn,
			AuthPassword:    confPeerPassword,
		},
	}

	n.AfiSafis = make([]*gobgpapi.AfiSafi, 0)
	for _, f := range []string{"ipv4-unicast", "ipv6-unicast"} {
		rf, err := bgp.GetRouteFamily(f)
		if err != nil {
			return nil, err
		}

		afi, safi := bgp.RouteFamilyToAfiSafi(rf)
		family := &gobgpapi.Family{
			Afi:  gobgpapi.Family_Afi(afi),
			Safi: gobgpapi.Family_Safi(safi),
		}

		n.AfiSafis = append(n.AfiSafis, &gobgpapi.AfiSafi{Config: &gobgpapi.AfiSafiConfig{Family: family}})
	}

	err = s.AddPeer(context.Background(), &gobgpapi.AddPeerRequest{Peer: n})
	if err != nil {
		return nil, err
	}

	return s, nil
}
