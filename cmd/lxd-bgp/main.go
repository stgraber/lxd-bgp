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

	"google.golang.org/protobuf/types/known/anypb"

	bgpAPI "github.com/osrg/gobgp/v3/api"
	bgpPacket "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	bgpServer "github.com/osrg/gobgp/v3/pkg/server"

	"github.com/lxc/lxd/client"
	"github.com/lxc/lxd/shared"
	lxdapi "github.com/lxc/lxd/shared/api"
)

var (
	confAsn           = uint32(0)
	confPeerAddresses = []string{}
	confPeerAsn       = []uint32{}
	confPeerPassword  = ""
	confUplinks       = []string{}
	confRouterID      = ""

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

	confPeerAsn = []uint32{}
	for _, entry := range strings.Split(os.Args[4], ",") {
		val, err = strconv.ParseUint(entry, 10, 32)
		if err != nil {
			return err
		}

		confPeerAsn = append(confPeerAsn, uint32(val))
	}

	confPeerAddresses = strings.Split(os.Args[5], ",")
	if len(os.Args) == 7 {
		confPeerPassword = os.Args[6]
	}

	// Validation.
	if len(confPeerAsn) > 1 && len(confPeerAsn) != len(confPeerAddresses) {
		return fmt.Errorf("ASN and addresses list length don't match")
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
		ev, err := c.GetEventsAllProjects()
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
}

func updatePrefixes(s *bgpServer.BgpServer, c lxd.InstanceServer) error {
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

		if u.Managed {
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
							if i.Location != "none" && i.Location != hostname {
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
									for _, prefix := range strings.Split(dev["ipv4.routes.external"], ",") {
										prefix = strings.TrimSpace(prefix)

										_, ipnet, err := net.ParseCIDR(prefix)
										if err != nil {
											fmt.Printf("WARN: skipping %q: %v\n", instance, err)
											continue
										}

										newAdv = append(newAdv, advertisement{nexthop: net.ParseIP(ovnV4), prefix: *ipnet})
									}
								}

								if dev["ipv6.routes.external"] != "" {
									for _, prefix := range strings.Split(dev["ipv6.routes.external"], ",") {
										prefix = strings.TrimSpace(prefix)

										_, ipnet, err := net.ParseCIDR(prefix)
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
		} else {
			// Go through all instances in all projects (slow path).
			projects, err := c.GetProjectNames()
			if err != nil {
				return err
			}

			for _, proj := range projects {
				// Go through the instances.
				instances, err := c.UseProject(proj).GetInstances(lxdapi.InstanceTypeAny)
				if err != nil {
					return err
				}

				for _, i := range instances {
					// Only announce our local instances.
					if i.Location != "none" && i.Location != hostname {
						continue
					}

					// Skip any instance that's not running.
					if i.StatusCode != lxdapi.Running {
						continue
					}

					// Go through devices.
					for _, d := range i.ExpandedDevices {
						val, ok := d["user.bgp.routes"]
						if !ok {
							continue
						}

						prefixes := strings.Split(val, ",")

						for _, prefix := range prefixes {
							prefix = strings.TrimSpace(prefix)
							fields := strings.Split(prefix, "_")
							if len(fields) != 2 {
								fmt.Printf("WARN: skipping %q: bad value\n", i.Name)
								continue
							}

							_, ipnet, err := net.ParseCIDR(fields[0])
							if err != nil {
								fmt.Printf("WARN: skipping %q: %v\n", i.Name, err)
								continue
							}

							newAdv = append(newAdv, advertisement{nexthop: net.ParseIP(fields[1]), prefix: *ipnet})
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
			err := s.DeletePath(context.Background(), &bgpAPI.DeletePathRequest{Uuid: prev.uuid})
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

func addRoute(s *bgpServer.BgpServer, subnet net.IPNet, nexthop net.IP) ([]byte, error) {
	prefixLen, _ := subnet.Mask.Size()
	prefix := subnet.IP.String()

	nlri, _ := anypb.New(&bgpAPI.IPAddressPrefix{
		Prefix:    prefix,
		PrefixLen: uint32(prefixLen),
	})

	aOrigin, _ := anypb.New(&bgpAPI.OriginAttribute{
		Origin: 0,
	})

	var uuid []byte
	if subnet.IP.To4() != nil {
		aNextHop, _ := anypb.New(&bgpAPI.NextHopAttribute{
			NextHop: nexthop.String(),
		})

		resp, err := s.AddPath(context.Background(), &bgpAPI.AddPathRequest{
			Path: &bgpAPI.Path{
				Family: &bgpAPI.Family{Afi: bgpAPI.Family_AFI_IP, Safi: bgpAPI.Family_SAFI_UNICAST},
				Nlri:   nlri,
				Pattrs: []*anypb.Any{aOrigin, aNextHop},
			},
		})
		if err != nil {
			return nil, err
		}

		uuid = resp.Uuid
	} else {
		family := &bgpAPI.Family{
			Afi:  bgpAPI.Family_AFI_IP6,
			Safi: bgpAPI.Family_SAFI_UNICAST,
		}

		v6Attrs, _ := anypb.New(&bgpAPI.MpReachNLRIAttribute{
			Family:   family,
			NextHops: []string{nexthop.String()},
			Nlris:    []*anypb.Any{nlri},
		})

		resp, err := s.AddPath(context.Background(), &bgpAPI.AddPathRequest{
			Path: &bgpAPI.Path{
				Family: family,
				Nlri:   nlri,
				Pattrs: []*anypb.Any{aOrigin, v6Attrs},
			},
		})
		if err != nil {
			return nil, err
		}

		uuid = resp.Uuid
	}

	return uuid, nil
}

func runBgp() (*bgpServer.BgpServer, error) {
	// Start the server.
	s := bgpServer.NewBgpServer()
	go s.Serve()

	// Main configuration.
	conf := &bgpAPI.Global{
		RouterId: confRouterID,
		Asn:      confAsn,
		Families: []uint32{0, 1},
	}

	err := s.StartBgp(context.Background(), &bgpAPI.StartBgpRequest{Global: conf})
	if err != nil {
		return nil, err
	}

	// Neighbor configuration.
	for i, confPeerAddress := range confPeerAddresses {
		asn := confPeerAsn[0]
		if len(confPeerAsn) > 1 {
			asn = confPeerAsn[i]
		}

		n := &bgpAPI.Peer{
			Conf: &bgpAPI.PeerConf{
				NeighborAddress: confPeerAddress,
				PeerAsn:         asn,
				AuthPassword:    confPeerPassword,
			},
			EbgpMultihop: &bgpAPI.EbgpMultihop{
				Enabled:     true,
				MultihopTtl: 4,
			},
			GracefulRestart: &bgpAPI.GracefulRestart{
				Enabled:     true,
				RestartTime: 120,
			},
		}

		n.AfiSafis = make([]*bgpAPI.AfiSafi, 0)
		for _, f := range []string{"ipv4-unicast", "ipv6-unicast"} {
			rf, err := bgpPacket.GetRouteFamily(f)
			if err != nil {
				return nil, err
			}

			afi, safi := bgpPacket.RouteFamilyToAfiSafi(rf)
			family := &bgpAPI.Family{
				Afi:  bgpAPI.Family_Afi(afi),
				Safi: bgpAPI.Family_Safi(safi),
			}

			n.AfiSafis = append(n.AfiSafis, &bgpAPI.AfiSafi{
				MpGracefulRestart: &bgpAPI.MpGracefulRestart{
					Config: &bgpAPI.MpGracefulRestartConfig{
						Enabled: true,
					},
				},
				Config: &bgpAPI.AfiSafiConfig{Family: family},
			})
		}

		err = s.AddPeer(context.Background(), &bgpAPI.AddPeerRequest{Peer: n})
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}
