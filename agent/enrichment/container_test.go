package enrichment

import (
	"strings"
	"testing"
)

// enrichCID is a container ID as it appears in cgroup paths. The Docker v2
// line below is the real /proc/<pid>/cgroup of a container on
// drl-nuc8i3bek (Ubuntu 22.10, cgroup v2, systemd driver); the others
// follow the layout each runtime and cgroup driver uses.
const (
	enrichCID   = "bcffe54a187e2a1f4aa4ea89ca5f369b79ddfa3da92cb3eb012784d479c6a36d"
	enrichOuter = "6f995b8bbaaa4354f2de9d90e0c6b64acfaa530218f809877854abac8f1f56d1"
	// Kubernetes pod UID: dashes in cgroupfs paths, underscores in systemd
	// slice names.
	enrichPodDash  = "3f6e5d2c-8a1b-4c3d-9e8f-7a6b5c4d3e2f"
	enrichPodUnder = "3f6e5d2c_8a1b_4c3d_9e8f_7a6b5c4d3e2f"
)

// enrichCgroupV1 builds a cgroup v1 /proc/<pid>/cgroup file with every
// controller hierarchy at path, as the cgroupfs driver lays it out.
func enrichCgroupV1(path string) string {
	return strings.Join([]string{
		"12:pids:" + path,
		"11:hugetlb:" + path,
		"10:net_cls,net_prio:" + path,
		"9:perf_event:" + path,
		"8:cpuset:" + path,
		"7:freezer:" + path,
		"6:memory:" + path,
		"5:devices:" + path,
		"4:blkio:" + path,
		"3:cpu,cpuacct:" + path,
		"2:rdma:/",
		"1:name=systemd:" + path,
		"",
	}, "\n")
}

func TestEnrichContainerIDByRuntime(t *testing.T) {
	cases := []struct {
		name    string
		cgroup  string // /proc/<pid>/cgroup content
		wantV2  string
		wantCID string
	}{
		// Docker
		{"docker v2 systemd driver (drl-nuc8i3bek)",
			"0::/system.slice/docker-" + enrichCID + ".scope\n",
			"/system.slice/docker-" + enrichCID + ".scope", enrichCID},
		{"docker v2 cgroupfs driver",
			"0::/docker/" + enrichCID + "\n",
			"/docker/" + enrichCID, enrichCID},
		{"docker v1 cgroupfs driver",
			enrichCgroupV1("/docker/" + enrichCID), "", enrichCID},
		{"docker v1 systemd driver",
			enrichCgroupV1("/system.slice/docker-" + enrichCID + ".scope"), "", enrichCID},
		{"docker-in-docker reports the inner container",
			"0::/docker/" + enrichOuter + "/docker/" + enrichCID + "\n",
			"/docker/" + enrichOuter + "/docker/" + enrichCID, enrichCID},

		// containerd (CRI plugin, Kubernetes)
		{"containerd v2 systemd driver",
			"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + enrichPodUnder + ".slice/cri-containerd-" + enrichCID + ".scope\n",
			"/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + enrichPodUnder + ".slice/cri-containerd-" + enrichCID + ".scope", enrichCID},
		{"containerd v1 cgroupfs driver",
			enrichCgroupV1("/kubepods/besteffort/pod" + enrichPodDash + "/" + enrichCID), "", enrichCID},
		{"containerd v1 systemd driver",
			enrichCgroupV1("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + enrichPodUnder + ".slice/cri-containerd-" + enrichCID + ".scope"), "", enrichCID},

		// CRI-O
		{"cri-o v2 systemd driver",
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + enrichPodUnder + ".slice/crio-" + enrichCID + ".scope\n",
			"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + enrichPodUnder + ".slice/crio-" + enrichCID + ".scope", enrichCID},
		{"cri-o v1 cgroupfs driver",
			enrichCgroupV1("/kubepods/burstable/pod" + enrichPodDash + "/crio-" + enrichCID), "", enrichCID},
		{"cri-o v1 systemd driver",
			enrichCgroupV1("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + enrichPodUnder + ".slice/crio-" + enrichCID + ".scope"), "", enrichCID},
		{"cri-o conmon is a host process",
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + enrichPodUnder + ".slice/crio-conmon-" + enrichCID + ".scope\n",
			"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + enrichPodUnder + ".slice/crio-conmon-" + enrichCID + ".scope", ""},

		// libpod (Podman)
		{"podman v2 rootful",
			"0::/machine.slice/libpod-" + enrichCID + ".scope/container\n",
			"/machine.slice/libpod-" + enrichCID + ".scope/container", enrichCID},
		{"podman v2 rootless",
			"0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + enrichCID + ".scope/container\n",
			"/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + enrichCID + ".scope/container", enrichCID},
		{"podman v2 without the container sub-cgroup",
			"0::/machine.slice/libpod-" + enrichCID + ".scope\n",
			"/machine.slice/libpod-" + enrichCID + ".scope", enrichCID},
		{"podman v1 cgroupfs driver",
			enrichCgroupV1("/libpod_parent/libpod-" + enrichCID), "", enrichCID},
		{"podman v1 systemd driver",
			enrichCgroupV1("/machine.slice/libpod-" + enrichCID + ".scope"), "", enrichCID},
		{"podman conmon is a host process",
			"0::/machine.slice/libpod-conmon-" + enrichCID + ".scope\n",
			"/machine.slice/libpod-conmon-" + enrichCID + ".scope", ""},

		// Hybrid host: the v2 line names the shim's unit, a v1 hierarchy
		// names the container.
		{"hybrid v1+v2, container only in v1",
			strings.TrimSuffix(enrichCgroupV1("/docker/"+enrichCID), "\n") + "\n0::/system.slice/containerd.service\n",
			"/system.slice/containerd.service", enrichCID},

		// Not containers
		{"host login session", "0::/user.slice/user-1000.slice/session-2.scope\n",
			"/user.slice/user-1000.slice/session-2.scope", ""},
		{"dockerd itself", "0::/system.slice/docker.service\n", "/system.slice/docker.service", ""},
		{"init", "0::/init.scope\n", "/init.scope", ""},
		{"v1 host process", enrichCgroupV1("/user.slice/user-1000.slice/session-2.scope"), "", ""},
		{"63 hex digits is not an ID", "0::/docker/" + enrichCID[1:] + "\n", "/docker/" + enrichCID[1:], ""},
		{"empty file", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v2, cid := parseProcCgroup(c.cgroup)
			if v2 != c.wantV2 {
				t.Errorf("v2 path = %q, want %q", v2, c.wantV2)
			}
			if cid != c.wantCID {
				t.Errorf("container ID = %q, want %q", cid, c.wantCID)
			}
		})
	}
}
