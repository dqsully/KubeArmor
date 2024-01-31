// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"strings"

	"github.com/cilium/ebpf"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type RuleList map[InnerKey]Rule
type Rule uint32

const (
	RULE_TYPE_FILE    = 1
	RULE_TYPE_PROCESS = 2
	RULE_TYPE_NETWORK = 3
	RULE_TYPE_DEFAULT = 0xFF

	RULE_OFSET__BY_OWNER = 4

	RULE_OFFSET_FILE_READ                = 0
	RULE_OFFSET_FILE_READ_BY_OWNER       = 4
	RULE_OFFSET_FILE_WRITE               = 8
	RULE_OFFSET_FILE_WRITE_BY_OWNER      = 12
	RULE_OFFSET_PROCESS_EXECUTE          = 16
	RULE_OFFSET_PROCESS_EXECUTE_BY_OWNER = 20

	RULE_OFFSET_NETWORK = 0

	RULE_OFFSET_DEFAULT_FILE    = 0
	RULE_OFFSET_DEFAULT_PROCESS = 4
	RULE_OFFSET_DEFAULT_NETWORK = 8

	RULE_FLAG_ALLOW     = Rule(1)
	RULE_FLAG_LOG       = Rule(2)
	RULE_FLAG_RECURSIVE = Rule(4)
	RULE_FLAG_HINT      = Rule(8)

	RULE_NONE  = Rule(0)
	RULE_ALLOW = RULE_FLAG_ALLOW
	RULE_BLOCK = RULE_FLAG_LOG
	RULE_AUDIT = RULE_FLAG_LOG | RULE_FLAG_ALLOW

	RULE_MASK_ACTION = Rule(RULE_FLAG_ALLOW | RULE_FLAG_LOG)
)

// Protocol Identifiers for Network Rules
//
// Pulled from https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers and
// lower-cased
var protocols = map[string]uint8{
	"any":             0,
	"icmp":            1,
	"igmp":            2,
	"ggp":             3,
	"ip-in-ip":        4,
	"st":              5,
	"tcp":             6,
	"cbt":             7,
	"egp":             8,
	"igp":             9,
	"bnn-rcc-mon":     10,
	"nvp-ii":          11,
	"pup":             12,
	"argus":           13,
	"emcon":           14,
	"xnet":            15,
	"chaos":           16,
	"udp":             17,
	"mux":             18,
	"dcn-meas":        19,
	"hmp":             20,
	"prm":             21,
	"xns-idp":         22,
	"trunk-1":         23,
	"trunk-2":         24,
	"leaf-1":          25,
	"leaf-2":          26,
	"rdp":             27,
	"irtp":            28,
	"iso-tp4":         29,
	"netblt":          30,
	"mfe-nsp":         31,
	"merit-inp":       32,
	"dccp":            33,
	"3pc":             34,
	"idpr":            35,
	"xtp":             36,
	"ddp":             37,
	"idpr-cmtp":       38,
	"tp++":            39,
	"il":              40,
	"ipv6":            41,
	"sdrp":            42,
	"ipv6-route":      43,
	"ipv6-frag":       44,
	"idrp":            45,
	"rsvp":            46,
	"gre":             47,
	"dsr":             48,
	"bna":             49,
	"esp":             50,
	"ah":              51,
	"i-nlsp":          52,
	"swipe":           53,
	"narp":            54,
	"mobile":          55,
	"tlsp":            56,
	"skip":            57,
	"ipv6-icmp":       58,
	"ipv6-nonxt":      59,
	"ipv6-opts":       60,
	"cftp":            62,
	"sat-expak":       64,
	"kryptolan":       65,
	"rvd":             66,
	"ippc":            67,
	"sat-mon":         69,
	"visa":            70,
	"ipcu":            71,
	"cpnx":            72,
	"cphb":            73,
	"wsn":             74,
	"pvp":             75,
	"br-sat-mon":      76,
	"sun-nd":          77,
	"wb-mon":          78,
	"wb-expak":        79,
	"iso-ip":          80,
	"vmtp":            81,
	"secure-vmtp":     82,
	"vines":           83,
	"ttp":             84,
	"nsfnet-igp":      85,
	"dgp":             86,
	"tcf":             87,
	"eigrp":           88,
	"ospf":            89,
	"sprite-rpc":      90,
	"larp":            91,
	"mtp":             92,
	"ax.25":           93,
	"os":              94,
	"micp":            95,
	"scc-sp":          96,
	"etherip":         97,
	"encap":           98,
	"gmtp":            100,
	"ifmp":            101,
	"pnni":            102,
	"pim":             103,
	"aris":            104,
	"scps":            105,
	"qnx":             106,
	"a/n":             107,
	"ipcomp":          108,
	"snp":             109,
	"compaq-peer":     110,
	"ipx-in-ip":       111,
	"vrrp":            112,
	"pgm":             113,
	"l2tp":            115,
	"ddx":             116,
	"iatp":            117,
	"stp":             118,
	"srp":             119,
	"uti":             120,
	"smp":             121,
	"sm":              122,
	"ptp":             123,
	"isis":            124,
	"fire":            125,
	"crtp":            126,
	"crudp":           127,
	"sscopmce":        128,
	"iplt":            129,
	"sps":             130,
	"pipe":            131,
	"sctp":            132,
	"fc":              133,
	"rsvp-e2e-ignore": 134,
	"mobility-header": 135,
	"udplite":         136,
	"mpls-in-ip":      137,
	"manet":           138,
	"hip":             139,
	"shim6":           140,
	"wesp":            141,
	"rohc":            142,
	"ethernet":        143,
	"aggfrag":         144,
	"nsh":             145,
	"raw":             255,
}

var defaultPostureKey = InnerKey{
	Path:   [256]byte{RULE_TYPE_DEFAULT},
	Source: [256]byte{},
}

func (rl RuleList) AddStringRule(path, src string, rule Rule, offset int) {
	var key InnerKey

	copy(key.Path[:], path)
	copy(key.Source[:], src)

	rl.AddRule(key, rule, offset)
}

func (rl RuleList) AddRule(key InnerKey, rule Rule, offset int) {
	if (rl[key]>>offset)&RULE_MASK_ACTION == RULE_BLOCK {
		// If the old rule is block, it takes precedence over the new rule.
		// Remove those bits from the rule.
		rule &= ^RULE_MASK_ACTION
	}

	rl[key] |= rule << offset
}

func (rl RuleList) AddStringDirRule(path, src string, rule Rule, offset int, recursive bool) {
	var rflag = RULE_NONE
	if recursive {
		rflag = RULE_FLAG_RECURSIVE
	}

	var key InnerKey

	if src != "" {
		copy(key.Source[:], []byte(src))
	}

	// In case anything accesses the directory itself (as a file), add a rule
	// for just that
	copy(key.Path[:], strings.TrimSuffix(path, "/"))
	rl.AddRule(key, rule, offset)

	// Add the directory rule
	copy(key.Path[:], path)
	rl.AddRule(key, rule|rflag, offset)

	if len(path) > 0 {
		// Add hint flags for all parent directories

		prefix := path[0:1]
		prefixLen := 1

		if prefix == "$" {
			prefix = path[0:2]
			prefixLen = 2
		}

		paths := strings.Split(path[prefixLen:], "/")

		for i := 0; i < len(paths)-1; i++ {
			var key InnerKey
			path := prefix + strings.Join(paths[0:i], "/")

			if i > 0 {
				path += "/"
			}

			copy(key.Path[:], []byte(path))
			if src != "" {
				copy(key.Source[:], []byte(src))
			}

			rl.AddRule(key, RULE_FLAG_HINT, offset)
		}
	}
}

// UpdateContainerRules updates individual container map with new rules and
// resolves conflicting rules
func (be *BPFEnforcer) UpdateContainerRules(id string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) {
	newRules := make(RuleList)

	hasProcRule := false
	hasFileRule := false
	hasNetRule := false

	for _, secPolicy := range securityPolicies {
		rule := postureToRule(secPolicy.Spec.Action)

		if rule == RULE_NONE {
			be.Logger.Printf("Invalid posture %s for policy %s", secPolicy.Spec.Action, secPolicy.Metadata["policyName"])
			continue
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			hasProcRule = true

			offset := RULE_OFFSET_PROCESS_EXECUTE
			if path.OwnerOnly {
				offset = RULE_OFFSET_PROCESS_EXECUTE_BY_OWNER
			}

			if len(path.FromSource) == 0 {
				newRules.AddStringRule(path.Path, "", rule, offset)
			} else {
				for _, src := range path.FromSource {
					newRules.AddStringRule(path.Path, src.Path, rule, offset)
				}
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			hasProcRule = true

			offset := RULE_OFFSET_PROCESS_EXECUTE
			if dir.OwnerOnly {
				offset = RULE_OFFSET_PROCESS_EXECUTE_BY_OWNER
			}

			if len(dir.FromSource) == 0 {
				newRules.AddStringDirRule(dir.Directory, "", rule, offset, dir.Recursive)
			} else {
				for _, src := range dir.FromSource {
					newRules.AddStringDirRule(dir.Directory, src.Path, rule, offset, dir.Recursive)
				}
			}
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			hasFileRule = true

			var offset int

			if path.ReadOnly {
				if path.OwnerOnly {
					offset = RULE_OFFSET_FILE_READ_BY_OWNER
				} else {
					offset = RULE_OFFSET_FILE_READ
				}
			} else {
				if path.OwnerOnly {
					offset = RULE_OFFSET_FILE_WRITE_BY_OWNER
				} else {
					offset = RULE_OFFSET_FILE_WRITE
				}
			}

			if len(path.FromSource) == 0 {
				newRules.AddStringRule(path.Path, "", rule, offset)
			} else {
				for _, src := range path.FromSource {
					newRules.AddStringRule(path.Path, src.Path, rule, offset)
				}
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			hasFileRule = true

			var offset int

			if dir.ReadOnly {
				if dir.OwnerOnly {
					offset = RULE_OFFSET_FILE_READ_BY_OWNER
				} else {
					offset = RULE_OFFSET_FILE_READ
				}
			} else {
				if dir.OwnerOnly {
					offset = RULE_OFFSET_FILE_WRITE_BY_OWNER
				} else {
					offset = RULE_OFFSET_FILE_WRITE
				}
			}

			if len(dir.FromSource) == 0 {
				newRules.AddStringDirRule(dir.Directory, "", rule, offset, dir.Recursive)
			} else {
				for _, src := range dir.FromSource {
					newRules.AddStringDirRule(dir.Directory, src.Path, rule, offset, dir.Recursive)
				}
			}
		}

		for _, net := range secPolicy.Spec.Network.MatchProtocols {
			hasNetRule = true

			protocol, ok := protocols[strings.ToLower(net.Protocol)]
			if !ok {
				continue
			}

			var pathRaw [3]byte
			pathRaw[0] = RULE_TYPE_NETWORK
			pathRaw[1] = protocol
			pathRaw[2] = 0

			path := string(pathRaw[:])

			if len(net.FromSource) == 0 {
				newRules.AddStringRule(path, "", rule, 0)
			} else {
				for _, src := range net.FromSource {
					newRules.AddStringRule(path, src.Path, rule, 0)
				}
			}
		}
	}

	enforceAll := cfg.GlobalCfg.EnforceAllDefaultPolicy && (hasProcRule || hasFileRule || hasNetRule)

	if hasProcRule || enforceAll {
		newRules.AddRule(defaultPostureKey, postureToRule(defaultPosture.FileAction), RULE_OFFSET_DEFAULT_PROCESS)
	}
	if hasFileRule || enforceAll {
		newRules.AddRule(defaultPostureKey, postureToRule(defaultPosture.FileAction), RULE_OFFSET_DEFAULT_FILE)
	}
	if hasNetRule || enforceAll {
		newRules.AddRule(defaultPostureKey, postureToRule(defaultPosture.NetworkAction), RULE_OFFSET_DEFAULT_NETWORK)
	}

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()

	// Check if Container ID is registered in Map or not
	kv, ok := be.ContainerMap[id]
	if !ok {
		// It maybe possible that CRI has unregistered the containers but K8s
		// construct still has not sent this update while the policy was being
		// applied, so the need to check if the container is present in the map
		// before we apply policy.
		return
	}

	if len(newRules) == 0 {
		// All Policies removed for the container
		be.Logger.Printf("Deleting inner map for %s", id)
		be.DeleteContainerInnerMap(id)
		return
	}

	if kv.Map == nil {
		// We create the inner map only when we have policies specific to that
		be.Logger.Printf("Creating inner map for %s", id)
		be.CreateContainerInnerMap(id)
		kv = be.ContainerMap[id]
	}

	oldRules := kv.Rules
	keysToDelete := []InnerKey{}

	// Delete old rules
	for key := range oldRules {
		if _, ok := newRules[key]; !ok {
			keysToDelete = append(keysToDelete, key)
		}
	}

	kv.Map.BatchDelete(keysToDelete, &ebpf.BatchOptions{})

	// Add/overwrite new rules
	for key, val := range newRules {
		if val != oldRules[key] {
			if err := kv.Map.Put(key, val); err != nil {
				be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
			}
		}
	}

	// Save a copy of the new rules for next time, since we can't easily read
	// from the eBPF map itself
	kv.Rules = newRules
	be.ContainerMap[id] = kv
}

func postureToRule(posture string) Rule {
	switch strings.ToLower(posture) {
	case "allow":
		return RULE_ALLOW
	case "block":
		return RULE_BLOCK
	case "audit":
		return RULE_AUDIT
	default:
		return RULE_NONE
	}
}
