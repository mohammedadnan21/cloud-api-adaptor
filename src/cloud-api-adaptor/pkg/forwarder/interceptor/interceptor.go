// (C) Copyright IBM Corp. 2022.
// SPDX-License-Identifier: Apache-2.0

package interceptor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	retry "github.com/avast/retry-go/v4"
	pb "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"github.com/moby/sys/mountinfo"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-api-adaptor/pkg/util/agentproto"
)

const (
	volumeTargetPathKey  = "io.confidentialcontainers.org.peerpodvolumes.target_path"
	cloudVolumesKey      = "io.confidentialcontainers.org.cloud_volumes"
	cloudVolumeMountBase = "/run/cloud-volumes"
	volumeCheckInterval  = 5 * time.Second
	volumeCheckTimeout   = 3 * time.Minute
)

var logger = log.New(log.Writer(), "[forwarder/interceptor] ", log.LstdFlags|log.Lmsgprefix)

type Interceptor interface {
	agentproto.Redirector
}

type interceptor struct {
	agentproto.Redirector

	nsPath string
}

func dial(ctx context.Context, agentSocket string) (net.Conn, error) {

	var conn net.Conn

	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()

	logger.Printf("Trying to establish agent connection to %s", agentSocket)
	err := retry.Do(
		func() error {
			var err error
			conn, err = (&net.Dialer{}).DialContext(ctx, "unix", agentSocket)
			return err
		},
		retry.Context(ctx),
	)

	if err != nil {
		err = fmt.Errorf("failed to establish agent connection to %s: %w", agentSocket, err)
		logger.Print(err)
		return nil, err
	}

	logger.Printf("established agent connection to %s", agentSocket)
	return conn, nil
}

func NewInterceptor(agentSocket, nsPath string) Interceptor {

	agentDialer := func(ctx context.Context) (net.Conn, error) {
		return dial(ctx, agentSocket)
	}

	redirector := agentproto.NewRedirector(agentDialer)

	return &interceptor{
		Redirector: redirector,
		nsPath:     nsPath,
	}
}

func (i *interceptor) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*emptypb.Empty, error) {

	logger.Printf("CreateContainer: containerID:%s", req.ContainerId)

	// Specify the network namespace path in the container spec
	req.OCI.Linux.Namespaces = append(req.OCI.Linux.Namespaces, &pb.LinuxNamespace{
		Type: string(specs.NetworkNamespace),
		Path: i.nsPath,
	})

	logger.Printf("    namespaces:")
	for _, ns := range req.OCI.Linux.Namespaces {
		logger.Printf("    %s: %q", ns.Type, ns.Path)
	}

	// Handle cloud volumes: detect device, format if needed, mount, and
	// bind-mount into the container's mount namespace
	if cvJSON, ok := req.OCI.Annotations[cloudVolumesKey]; ok && cvJSON != "" {
		var cloudVolumes map[string]map[string]string
		if err := json.Unmarshal([]byte(cvJSON), &cloudVolumes); err != nil {
			logger.Printf("failed to parse cloud_volumes annotation: %v", err)
		} else {
			for volName, volInfo := range cloudVolumes {
				mountPoint := volInfo["mount_point"]
				fsType := volInfo["fs_type"]
				lunStr := volInfo["lun"]
				if mountPoint == "" || lunStr == "" {
					logger.Printf("cloud volume %s missing mount_point or lun, skipping", volName)
					continue
				}
				lunIdx, err := strconv.Atoi(lunStr)
				if err != nil {
					logger.Printf("cloud volume %s has invalid lun %q: %v", volName, lunStr, err)
					continue
				}

				device, err := findDataDiskDevice(lunIdx)
				if err != nil {
					return nil, fmt.Errorf("cloud volume %s: %w", volName, err)
				}
				logger.Printf("cloud volume %s: LUN %d -> device %s", volName, lunIdx, device)

				hostMountPoint := filepath.Join(cloudVolumeMountBase, volName)
				if err := os.MkdirAll(hostMountPoint, 0o755); err != nil {
					return nil, fmt.Errorf("creating mount point for %s: %w", volName, err)
				}

				if err := waitForDevice(device); err != nil {
					return nil, fmt.Errorf("cloud volume %s device %s not available: %w", volName, device, err)
				}

				if err := formatAndMount(device, hostMountPoint, fsType); err != nil {
					return nil, fmt.Errorf("failed to mount cloud volume %s at %s: %w", volName, hostMountPoint, err)
				}

				// Rewrite mount source to point to the host mount point
				for idx, m := range req.OCI.Mounts {
					if m.Destination == mountPoint {
						req.OCI.Mounts[idx].Source = hostMountPoint
						req.OCI.Mounts[idx].Type = "bind"
						logger.Printf("cloud volume %s: rewrote mount source to %s", volName, hostMountPoint)
						break
					}
				}
			}
		}
	}

	volumeTargetPath := req.OCI.Annotations[volumeTargetPathKey]
	volumeTargetPathSlice := strings.Split(volumeTargetPath, ",")
	if len(req.OCI.Mounts) > 0 {
		for _, m := range req.OCI.Mounts {
			if _, err := os.Stat(m.Source); os.IsNotExist(err) && m.Type == "bind" {
				logger.Printf("mount source %s doesn't exist, try to create", m.Source)
				if err = os.MkdirAll(m.Source, os.ModePerm); err != nil {
					logger.Printf("Failed to create dir: %v", err)
				}
			}
			for _, s := range volumeTargetPathSlice {
				if isTargetPath(m.Source, strings.TrimSpace(s)) {
					logger.Printf("Waiting for device mounted to: %s", m.Source)
					err := waitForDeviceMounted(ctx, m.Source)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	res, err := i.Redirector.CreateContainer(ctx, req)

	if err != nil {
		logger.Printf("CreateContainer failed with error: %v", err)
	}

	return res, err
}

func isTargetPath(path, targetPath string) bool {
	return targetPath != "" && targetPath == path
}

func waitForDeviceMounted(ctx context.Context, path string) error {

	ctx, cancel := context.WithTimeout(ctx, volumeCheckTimeout)
	defer cancel()

	err := retry.Do(
		func() error {
			isMounted, err := mountinfo.Mounted(path)
			if err != nil {
				logger.Printf("Mounted check error: %v", err)
				return err
			}

			if isMounted {
				logger.Printf("Device has been mounted to %s", path)
				return nil
			} else {
				err = fmt.Errorf("Device has not been mounted to %s", path)
				logger.Print(err)
				return err
			}
		},
		retry.Attempts(0),
		retry.Context(ctx),
		retry.MaxDelay(volumeCheckInterval),
	)

	if err != nil {
		err = fmt.Errorf("Timeout waiting for device to mount to %s: %w", path, err)
		logger.Print(err)
		return err
	}

	return nil

}

func (i *interceptor) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*emptypb.Empty, error) {

	logger.Printf("StartContainer: containerID:%s", req.ContainerId)

	res, err := i.Redirector.StartContainer(ctx, req)

	if err != nil {
		logger.Printf("StartContainer failed with error: %v", err)
	}

	return res, err
}

func (i *interceptor) RemoveContainer(ctx context.Context, req *pb.RemoveContainerRequest) (*emptypb.Empty, error) {

	logger.Printf("RemoveContainer: containerID:%s", req.ContainerId)

	res, err := i.Redirector.RemoveContainer(ctx, req)

	if err != nil {
		logger.Printf("RemoveContainer failed with error: %v", err)
	}
	return res, err
}

func (i *interceptor) CreateSandbox(ctx context.Context, req *pb.CreateSandboxRequest) (*emptypb.Empty, error) {

	logger.Printf("CreateSandbox: hostname:%s sandboxId:%s", req.Hostname, req.SandboxId)

	if len(req.Dns) > 0 {
		logger.Print("    dns:")
		for _, d := range req.Dns {
			logger.Printf("        %s", d)
		}

		logger.Print("      Eliminated the DNS setting above from CreateSandboxRequest to stop updating /etc/resolv.conf on the peer pod VM")
		logger.Print("      See https://github.com/confidential-containers/cloud-api-adaptor/issues/98 for the details.")
		logger.Println()
		req.Dns = nil
	}

	res, err := i.Redirector.CreateSandbox(ctx, req)

	if err != nil {
		logger.Printf("CreateSandbox failed with error: %v", err)
	}

	return res, err
}

func (i *interceptor) DestroySandbox(ctx context.Context, req *pb.DestroySandboxRequest) (*emptypb.Empty, error) {

	logger.Printf("DestroySandbox")

	res, err := i.Redirector.DestroySandbox(ctx, req)

	if err != nil {
		logger.Printf("DestroySandbox failed with error: %v", err)
	}

	return res, err
}

// findDataDiskDevice locates the block device for the given LUN index.
// It tries Azure-specific symlinks first, then falls back to scanning sysfs.
func findDataDiskDevice(lunIdx int) (string, error) {
	// Azure udev symlinks (from azure-vm-utils package)
	azurePaths := []string{
		fmt.Sprintf("/dev/disk/azure/data/by-lun/%d", lunIdx),
		fmt.Sprintf("/dev/disk/azure/scsi1/lun%d", lunIdx),
	}
	for _, p := range azurePaths {
		if target, err := filepath.EvalSymlinks(p); err == nil {
			logger.Printf("Found data disk via Azure symlink %s -> %s", p, target)
			return target, nil
		}
	}

	// Hyper-V by-path: /dev/disk/by-path/acpi-VMBUS:00-vmbus-<guid>-lun-<N>
	byPathDir := "/dev/disk/by-path"
	if entries, err := os.ReadDir(byPathDir); err == nil {
		lunSuffix := fmt.Sprintf("-lun-%d", lunIdx)
		for _, e := range entries {
			name := e.Name()
			if strings.Contains(name, "vmbus") && strings.HasSuffix(name, lunSuffix) && !strings.Contains(name, "part") {
				fullPath := filepath.Join(byPathDir, name)
				if target, err := filepath.EvalSymlinks(fullPath); err == nil {
					logger.Printf("Found data disk via by-path %s -> %s", fullPath, target)
					return target, nil
				}
			}
		}
	}

	// Fallback: find block devices without partitions (data disks typically
	// have no partition table, unlike OS/resource disks)
	sysBlock := "/sys/block"
	entries, err := os.ReadDir(sysBlock)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", sysBlock, err)
	}

	var candidates []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "sd") && !strings.HasPrefix(name, "nvme") {
			continue
		}
		partEntries, err := filepath.Glob(filepath.Join(sysBlock, name, name+"*"))
		if err != nil || len(partEntries) > 0 {
			continue
		}
		candidates = append(candidates, "/dev/"+name)
	}

	if lunIdx < len(candidates) {
		logger.Printf("Found data disk via sysfs heuristic: %s (lun=%d)", candidates[lunIdx], lunIdx)
		return candidates[lunIdx], nil
	}

	dumpBlockDeviceDiagnostics()
	return "", fmt.Errorf("no data disk found for LUN %d (candidates: %v)", lunIdx, candidates)
}

func dumpBlockDeviceDiagnostics() {
	logger.Printf("=== Block Device Diagnostics ===")
	if out, err := exec.Command("lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE").CombinedOutput(); err == nil {
		logger.Printf("lsblk:\n%s", string(out))
	}
	for _, dir := range []string{"/dev/disk/azure", "/dev/disk/by-path", "/dev/disk/by-id"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				full := filepath.Join(dir, e.Name())
				if target, err := os.Readlink(full); err == nil {
					logger.Printf("  %s -> %s", full, target)
				}
			}
		}
	}
}

func waitForDevice(device string) error {
	for attempt := 0; attempt < 30; attempt++ {
		if strings.HasPrefix(device, "/dev/disk/") {
			if _, err := os.Lstat(device); err == nil {
				return nil
			}
		} else {
			devName := filepath.Base(device)
			if _, err := os.Stat(filepath.Join("/sys/block", devName)); err == nil {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("device %s not available after 60s", device)
}

func formatAndMount(device, mountPoint, fsType string) error {
	if fsType == "" {
		fsType = "ext4"
	}

	// Try mounting first — if the disk already has a valid filesystem, this
	// avoids any risk of accidentally reformatting it.
	mountCmd := exec.Command("mount", "-t", fsType, device, mountPoint)
	if mountOut, mountErr := mountCmd.CombinedOutput(); mountErr == nil {
		logger.Printf("Mounted existing filesystem on %s at %s (type=%s)", device, mountPoint, fsType)
		return nil
	} else {
		logger.Printf("Initial mount of %s failed (expected for new disks): %s", device, strings.TrimSpace(string(mountOut)))
	}

	// Mount failed — check if there's any filesystem using blkid with retries.
	needsFormat := false
	for attempt := 0; attempt < 3; attempt++ {
		out, err := exec.Command("blkid", "-p", device).CombinedOutput()
		outStr := strings.TrimSpace(string(out))
		if err == nil && len(outStr) > 0 {
			autoMount := exec.Command("mount", device, mountPoint)
			if autoOut, autoErr := autoMount.CombinedOutput(); autoErr == nil {
				logger.Printf("Mounted %s at %s (auto-detected type from: %s)", device, mountPoint, outStr)
				return nil
			} else {
				return fmt.Errorf("device %s has filesystem signature (%s) but mount failed: %s", device, outStr, strings.TrimSpace(string(autoOut)))
			}
		}
		if err != nil {
			// Exit code 2 = no valid filesystem found (safe to format)
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
				needsFormat = true
				break
			}
			logger.Printf("blkid attempt %d for %s failed: %v (output: %s)", attempt+1, device, err, outStr)
			time.Sleep(2 * time.Second)
			continue
		}
		needsFormat = true
		break
	}

	if !needsFormat {
		return fmt.Errorf("cannot determine filesystem state of %s after retries; refusing to format to protect data", device)
	}

	logger.Printf("No filesystem on %s, formatting as %s", device, fsType)
	mkfsCmd := exec.Command("mkfs."+fsType, device)
	if mkfsOut, mkfsErr := mkfsCmd.CombinedOutput(); mkfsErr != nil {
		return fmt.Errorf("mkfs.%s on %s failed: %s: %w", fsType, device, strings.TrimSpace(string(mkfsOut)), mkfsErr)
	}
	logger.Printf("Formatted %s as %s", device, fsType)

	mountCmd2 := exec.Command("mount", "-t", fsType, device, mountPoint)
	if mountOut, mountErr := mountCmd2.CombinedOutput(); mountErr != nil {
		return fmt.Errorf("mount after format %s -> %s failed: %s: %w", device, mountPoint, strings.TrimSpace(string(mountOut)), mountErr)
	}
	logger.Printf("Mounted %s at %s (type=%s)", device, mountPoint, fsType)
	return nil
}
