// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package filelessexec ...
package filelessexec

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang filelessexec  ../../BPF/filelessexec.bpf.c -type event -no-global-types -- -I/usr/include/ -O2 -g

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kubearmor/KubeArmor/KubeArmor/presets/base"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang filelessexec  ../../BPF/filelessexec.bpf.c -type event -no-global-types -- -I/usr/include/ -O2 -g

const (
	// NAME of preset
	NAME string = "FilelessExecutionPreset"
)

// NsKey struct
type NsKey struct {
	PidNS uint32
	MntNS uint32
}

// ContainerVal struct
type ContainerVal struct {
	NsKey  NsKey
	Policy string
}

// Preset struct
type Preset struct {
	base.Preset

	BPFContainerMap *ebpf.Map

	// events
	Events        *ringbuf.Reader
	EventsChannel chan []byte

	// ContainerID -> NsKey
	ContainerMap     map[string]ContainerVal
	ContainerMapLock *sync.RWMutex

	Link link.Link

	obj filelessexecObjects
}

// NewFilelessExecPreset creates an instance of FilelessExec Preset
func NewFilelessExecPreset() *Preset {
	p := &Preset{}
	p.ContainerMap = make(map[string]ContainerVal)
	p.ContainerMapLock = new(sync.RWMutex)
	return p
}

// Name returns name of Preset
func (p *Preset) Name() string {
	return NAME
}

// RegisterPreset register FilelessExec preset
func (p *Preset) RegisterPreset(logger *fd.Feeder, monitor *mon.SystemMonitor) (base.PresetInterface, error) {

	if logger.Enforcer != "BPFLSM" {
		// it's based on active enforcer, it might possible that node support bpflsm but
		// current enforcer is not bpflsm
		return nil, errors.New("FilelessExecutionPreset not supported if bpflsm not supported")
	}

	p.Logger = logger
	p.Monitor = monitor
	var err error

	if err = rlimit.RemoveMemlock(); err != nil {
		p.Logger.Errf("Error removing rlimit %v", err)
		return nil, err // Doesn't require clean up so not returning err
	}

	p.Logger.Printf("Preset Pinpath: %s\n", monitor.PinPath)

	p.BPFContainerMap, _ = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 256,
		Pinning:    ebpf.PinByName,
		Name:       "fileless_exec_preset_containers",
	}, ebpf.MapOptions{
		PinPath: monitor.PinPath,
	})

	if err := loadFilelessexecObjects(&p.obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: monitor.PinPath,
		},
	}); err != nil {
		p.Logger.Errf("error loading BPF LSM objects: %v", err)
		return nil, err
	}

	p.Link, err = link.AttachLSM(link.LSMOptions{Program: p.obj.EnforceBprmCheckSecurity})
	if err != nil {
		p.Logger.Errf("opening lsm %s: %s", p.obj.EnforceBprmCheckSecurity.String(), err)
		return nil, err
	}

	p.Events, err = ringbuf.NewReader(p.obj.Events)
	if err != nil {
		p.Logger.Errf("opening ringbuf reader: %s", err)
		return nil, err
	}
	p.EventsChannel = make(chan []byte, mon.SyscallChannelSize)

	go p.TraceEvents()

	return p, nil

}

// TraceEvents traces events generated by bpflsm enforcer
func (p *Preset) TraceEvents() {

	if p.Events == nil {
		p.Logger.Err("ringbuf reader is nil, exiting trace events")
	}
	p.Logger.Print("Starting TraceEvents from FilelessExec Presets")
	go func() {
		for {

			record, err := p.Events.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// This should only happen when we call DestroyMonitor while terminating the process.
					// Adding a Warn just in case it happens at runtime, to help debug
					p.Logger.Warnf("Ring Buffer closed, exiting TraceEvents %s", err.Error())
					return
				}
				p.Logger.Warnf("Ringbuf error reading %s", err.Error())
				continue
			}

			p.EventsChannel <- record.RawSample

		}
	}()

	for {

		dataRaw := <-p.EventsChannel

		var event base.EventPreset

		if err := binary.Read(bytes.NewBuffer(dataRaw), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		readLink := true

		containerID := ""

		if event.PidID != 0 && event.MntID != 0 {
			containerID = p.Monitor.LookupContainerID(event.PidID, event.MntID)
		}

		log := p.Monitor.BuildLogBase(event.EventID, mon.ContextCombined{
			ContainerID: containerID,
			ContextSys: mon.SyscallContext{
				PID:  event.PID,
				PPID: event.PPID,
				UID:  event.UID,

				HostPID:  event.HostPID,
				HostPPID: event.HostPPID,
			},
		}, readLink)

		if ckv, ok := p.ContainerMap[containerID]; ok {
			log.PolicyName = ckv.Policy
			log.Type = "MatchedPolicy"
		}

		log.Operation = "Process"

		if event.Retval >= 0 {
			log.Result = "Passed"
		} else {
			log.Result = "Permission denied"
		}

		log.Enforcer = base.PRESET_ENFORCER + NAME

		if len(log.Source) == 0 {
			log.Source = string(bytes.Trim(event.Data.Source[:], "\x00"))
		}

		// memfd:, /dev/shm/*, /run/shm/*
		log.Resource = string(bytes.Trim(event.Data.Path[:], "\x00"))

		p.Logger.PushLog(log)

	}
}

// RegisterContainer registers a container to filelessexec preset
func (p *Preset) RegisterContainer(containerID string, pidns, mntns uint32) {
	ckv := NsKey{PidNS: pidns, MntNS: mntns}

	p.ContainerMapLock.Lock()
	defer p.ContainerMapLock.Unlock()
	p.Logger.Printf("[FilelessExec] Registered container with id: %s\n", containerID)
	p.ContainerMap[containerID] = ContainerVal{NsKey: ckv}
}

// UnregisterContainer func unregisters a container from filelessexec preset
func (p *Preset) UnregisterContainer(containerID string) {
	p.ContainerMapLock.Lock()
	defer p.ContainerMapLock.Unlock()

	if val, ok := p.ContainerMap[containerID]; ok {
		if err := p.DeleteContainerIDFromMap(containerID, val.NsKey); err != nil {
			p.Logger.Errf("error deleting container %s: %s", containerID, err.Error())
			return
		}
		p.Logger.Printf("[FilelessExec] Unregistered container with id: %s\n", containerID)
		delete(p.ContainerMap, containerID)
	}
}

// AddContainerIDToMap adds a container id to ebpf map
func (p *Preset) AddContainerIDToMap(id string, ckv NsKey, action string) error {
	p.Logger.Printf("[FilelessExec] adding container with id to anon_map exec map: %s\n", id)
	a := base.Block
	if action == "Audit" {
		a = base.Audit
	}
	if err := p.BPFContainerMap.Put(ckv, a); err != nil {
		p.Logger.Errf("error adding container %s to outer map: %s", id, err)
		return err
	}
	return nil
}

// DeleteContainerIDFromMap deletes a container id from ebpf map
func (p *Preset) DeleteContainerIDFromMap(id string, ckv NsKey) error {
	p.Logger.Printf("[FilelessExec] deleting container with id to anon_map exec map: %s\n", id)
	if err := p.BPFContainerMap.Delete(ckv); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			p.Logger.Errf("error deleting container %s in anon_map_exec_preset_containers map: %s", id, err.Error())
			return err
		}
	}
	return nil
}

// UpdateSecurityPolicies updates filelessexec policy for a given endpoint
func (p *Preset) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	var filelessExecPresetRulePresent bool
	for _, cid := range endPoint.Containers {
		filelessExecPresetRulePresent = false
		p.Logger.Printf("Updating container preset rules for %s", cid)
		for _, secPolicy := range endPoint.SecurityPolicies {
			for _, preset := range secPolicy.Spec.Presets {
				if preset == tp.FilelessExec {
					p.Logger.Printf("container matched for fileless exec rule: %s", cid)
					filelessExecPresetRulePresent = true
					p.ContainerMapLock.RLock()
					// Check if Container ID is registered in Map or not
					ckv, ok := p.ContainerMap[cid]
					p.ContainerMapLock.RUnlock()
					if !ok {
						// It maybe possible that CRI has unregistered the containers but K8s construct still has not sent this update while the policy was being applied,
						// so the need to check if the container is present in the map before we apply policy.
						p.Logger.Warnf("container not registered in map: %s", cid)

						return
					}
					ckv.Policy = secPolicy.Metadata["policyName"]
					p.ContainerMapLock.Lock()
					p.ContainerMap[cid] = ckv
					err := p.AddContainerIDToMap(cid, ckv.NsKey, secPolicy.Spec.Action)
					if err != nil {
						p.Logger.Warnf("updating policy for container %s :%s ", cid, err)
					}
					p.ContainerMapLock.Unlock()
				}
			}
		}
		if !filelessExecPresetRulePresent {
			p.ContainerMapLock.RLock()
			ckv := p.ContainerMap[cid]
			_ = p.DeleteContainerIDFromMap(cid, ckv.NsKey)
			p.ContainerMapLock.RUnlock()
		}
	}
}

// Destroy func gracefully destroys filelessexec preset
func (p *Preset) Destroy() error {
	if p == nil {
		return nil
	}
	var errBPFCleanUp error

	if err := p.obj.Close(); err != nil {
		p.Logger.Err(err.Error())
		errBPFCleanUp = errors.Join(errBPFCleanUp, err)
	}

	if err := p.Link.Close(); err != nil {
		p.Logger.Err(err.Error())
		errBPFCleanUp = errors.Join(errBPFCleanUp, err)
	}

	p.ContainerMapLock.Lock()

	if p.BPFContainerMap != nil {
		if err := p.BPFContainerMap.Unpin(); err != nil {
			p.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
		if err := p.BPFContainerMap.Close(); err != nil {
			p.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
	}

	p.ContainerMapLock.Unlock()

	if p.Events != nil {
		if err := p.Events.Close(); err != nil {
			p.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
	}

	p = nil
	return errBPFCleanUp
}
