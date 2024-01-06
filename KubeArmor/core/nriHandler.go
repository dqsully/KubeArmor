package core

import (
	"context"
	"fmt"
	"os"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// NRI Handler
var NRI *NRIHandler

type NRIContainerEvent struct {
	Deleted   bool
	Container tp.Container
}

// NRIHandler Structure
type NRIHandler struct {
	// NRI plugin stub
	stub stub.Stub

	// active containers
	containers map[string]tp.Container

	handleDeletedContainer func(tp.Container)
	handleNewContainer     func(tp.Container)
}

// NewNRIHandler Function
func NewNRIHandler(
	handleDeletedContainer func(tp.Container),
	handleNewContainer func(tp.Container),
) *NRIHandler {
	nri := &NRIHandler{}

	opts := []stub.Option{
		stub.WithSocketPath(cfg.GlobalCfg.NRISocket),
		stub.WithPluginIdx(cfg.GlobalCfg.NRIIndex),
	}

	stub, err := stub.New(nri, opts...)
	if err != nil {
		kg.Errf("Failed to create NRI stub: %s", err.Error())
		return nil
	}

	nri.containers = map[string]tp.Container{}
	nri.stub = stub
	nri.handleDeletedContainer = handleDeletedContainer
	nri.handleNewContainer = handleNewContainer

	return nri
}

func (nh *NRIHandler) Start() {
	go func() {
		err := nh.stub.Run(context.Background())
		if err != nil {
			kg.Errf("Failed to connect to NRI: %s", err.Error())
		}
	}()
}

func (nh *NRIHandler) Close() {
	nh.stub.Stop()
}

func (nh *NRIHandler) Synchronize(
	_ context.Context,
	_ []*api.PodSandbox,
	nriContainers []*api.Container,
) ([]*api.ContainerUpdate, error) {
	for _, nriContainer := range nriContainers {
		container := nriToKubeArmorContainer(nriContainer)
		container = nh.mergeContainer(container, false)

		// Overlapping namespaces _should_ be impossible here

		nh.handleNewContainer(container)
	}

	return nil, nil
}

func (nh *NRIHandler) StartContainer(
	_ context.Context,
	_ *api.PodSandbox,
	nriContainer *api.Container,
) error {
	container := nriToKubeArmorContainer(nriContainer)
	container = nh.mergeContainer(container, false)

	nh.handleNewContainer(container)

	return nil
}

func (nh *NRIHandler) StopContainer(
	_ context.Context,
	_ *api.PodSandbox,
	nriContainer *api.Container,
) ([]*api.ContainerUpdate, error) {
	// We handle StopContainer instead of RemoveContainer because the
	// RemoveContainer event is fired off asynchronously, and may occur after an
	// equivalent StartContainer event starts. This is a problem because
	// Containerd and/or Linux itself may reuse the same PID and mount
	// namespaces for a new container, meaning that runc's container setup
	// actions on the new container may be treated as happening in the old
	// container, logging them and possibly blocking them erroneously and
	// breaking new container setup.
	//
	// In contrast, StopContainer is synchronous, so we can be sure that the
	// we stop enforcing or logging on a container before it is deleted and
	// before Containerd creates a new replacement container.

	container := nriToKubeArmorContainer(nriContainer)
	container = nh.mergeContainer(container, true)

	delete(nh.containers, container.ContainerID)

	nh.handleDeletedContainer(container)

	return nil, nil
}

func (nh *NRIHandler) mergeContainer(container tp.Container, removing bool) tp.Container {
	if existing, ok := nh.containers[container.ContainerID]; ok {
		if existing.PidNS != 0 {
			container.PidNS = existing.PidNS
		}

		if existing.MntNS != 0 {
			container.MntNS = existing.MntNS
		}

		nh.containers[container.ContainerID] = container
	} else if !removing {
		nh.containers[container.ContainerID] = container
	}

	return container
}

func nriToKubeArmorContainer(nriContainer *api.Container) tp.Container {
	container := tp.Container{}

	container.ContainerID = nriContainer.Id
	container.ContainerName = nriContainer.Name

	container.NamespaceName = "Unknown"
	container.EndPointName = "Unknown"

	if _, ok := nriContainer.Labels["io.kubernetes.pod.namespace"]; ok {
		container.NamespaceName = nriContainer.Labels["io.kubernetes.pod.namespace"] // Pod namespace

		if _, ok := nriContainer.Labels["io.kubernetes.pod.name"]; ok {
			container.EndPointName = nriContainer.Labels["io.kubernetes.pod.name"] // Pod name
		}
	}

	// TODO: Not sure how to get the apparmor profile from NRI

	// Also, other container fields aren't filled in by containerdHandler, so
	// I'm assuming we don't need them

	// Read PID and mount namespaces from container root PID
	if nriContainer.Pid != 0 {
		nsPath := fmt.Sprintf("/proc/%d/ns", nriContainer.Pid)

		if data, err := os.Readlink(nsPath + "/pid"); err == nil {
			if _, err := fmt.Sscanf(data, "pid:[%d]", &container.PidNS); err != nil {
				kg.Warnf("Unable to get PidNS (%s, %s, %s)", nriContainer.Id, nriContainer.Pid, err.Error())
			}
		}

		if data, err := os.Readlink(nsPath + "/mnt"); err == nil {
			if _, err := fmt.Sscanf(data, "mnt:[%d]", &container.MntNS); err != nil {
				kg.Warnf("Unable to get MntNS (%s, %s, %s)", nriContainer.Id, nriContainer.Pid, err.Error())
			}
		}
	}

	return container
}

func (dm *KubeArmorDaemon) MonitorNRIEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	handleDeletedContainer := func(container tp.Container) {
		dm.ContainersLock.Lock()
		_, ok := dm.Containers[container.ContainerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return
		}
		if !dm.K8sEnabled {
			dm.EndPointsLock.Lock()
			dm.MatchandRemoveContainerFromEndpoint(container.ContainerID)
			dm.EndPointsLock.Unlock()
		}
		delete(dm.Containers, container.ContainerID)
		dm.ContainersLock.Unlock()

		// Can't update AppArmor profiles since we can't get them from
		// NRI

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.UnregisterContainer(container.ContainerID)
		}

		dm.Logger.Printf("Detected a container (removed/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)
	}

	handleNewContainer := func(container tp.Container) {
		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[container.ContainerID]; !ok {
			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()
		} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
			// this entry was updated by kubernetes before docker detects it
			// thus, we here use the info given by kubernetes instead of the info given by docker

			container.NamespaceName = dm.Containers[container.ContainerID].NamespaceName
			container.EndPointName = dm.Containers[container.ContainerID].EndPointName
			container.Labels = dm.Containers[container.ContainerID].Labels

			container.ContainerName = dm.Containers[container.ContainerID].ContainerName
			container.ContainerImage = dm.Containers[container.ContainerID].ContainerImage

			container.PolicyEnabled = dm.Containers[container.ContainerID].PolicyEnabled

			container.ProcessVisibilityEnabled = dm.Containers[container.ContainerID].ProcessVisibilityEnabled
			container.FileVisibilityEnabled = dm.Containers[container.ContainerID].FileVisibilityEnabled
			container.NetworkVisibilityEnabled = dm.Containers[container.ContainerID].NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = dm.Containers[container.ContainerID].CapabilitiesVisibilityEnabled

			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()

			dm.EndPointsLock.Lock()
			for idx, endPoint := range dm.EndPoints {
				if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {
					// update containers
					if !kl.ContainsElement(endPoint.Containers, container.ContainerID) {
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, container.ContainerID)
					}

					break
				}
			}
			dm.EndPointsLock.Unlock()
		} else {
			dm.ContainersLock.Unlock()
			return
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
		}

		if !dm.K8sEnabled {
			dm.ContainersLock.Lock()
			dm.EndPointsLock.Lock()
			dm.MatchandUpdateContainerSecurityPolicies(container.ContainerID)
			dm.EndPointsLock.Unlock()
			dm.ContainersLock.Unlock()
		}

		dm.Logger.Printf("Detected a container (added/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)
	}

	NRI = NewNRIHandler(handleDeletedContainer, handleNewContainer)

	// check if NRI exists
	if NRI == nil {
		return
	}

	NRI.Start()

	dm.Logger.Print("Started to monitor NRI events")
}
