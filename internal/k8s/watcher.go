// Package k8s provides Kubernetes metadata enrichment and pod watching.
package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// Watcher watches for pod lifecycle events and maintains a local cache.
type Watcher struct {
	client    kubernetes.Interface
	informer  cache.SharedIndexInformer
	stopCh    chan struct{}
	stopOnce  sync.Once // guards close(stopCh) against double-close panics
	logger    *slog.Logger

	// podCache maps container ID -> PodInfo
	mu       sync.RWMutex
	podCache map[string]*PodInfo
}

// PodInfo contains Kubernetes metadata for a pod.
type PodInfo struct {
	Name        string
	Namespace   string
	UID         string
	Labels      map[string]string
	Annotations map[string]string
	ContainerIDs []string
	NodeName    string
}

// WatcherConfig holds configuration for the pod watcher.
type WatcherConfig struct {
	KubeconfigPath string
	ResyncPeriod   time.Duration
}

// NewWatcher creates a new pod lifecycle watcher.
func NewWatcher(config WatcherConfig, logger *slog.Logger) (*Watcher, error) {
	client, err := createK8sClient(config.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("k8s/watcher: create client: %w", err)
	}

	w := &Watcher{
		client:   client,
		stopCh:   make(chan struct{}),
		logger:   logger.With("component", "k8s_watcher"),
		podCache: make(map[string]*PodInfo),
	}

	// Create informer factory
	factory := informers.NewSharedInformerFactoryWithOptions(
		client,
		config.ResyncPeriod,
		informers.WithNamespace(""), // Watch all namespaces
	)

	// Create pod informer
	w.informer = factory.Core().V1().Pods().Informer()

	// Add event handlers
	w.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.onPodAdd,
		UpdateFunc: w.onPodUpdate,
		DeleteFunc: w.onPodDelete,
	})

	return w, nil
}

// createK8sClient creates a Kubernetes client from config.
func createK8sClient(kubeconfigPath string) (kubernetes.Interface, error) {
	var config *rest.Config
	var err error

	if kubeconfigPath != "" {
		// Use provided kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
	} else {
		// Try in-cluster config first
		config, err = rest.InClusterConfig()
		if err != nil {
			// Fall back to default kubeconfig location
			home := os.Getenv("HOME")
			if home == "" {
				home = os.Getenv("USERPROFILE") // Windows
			}
			defaultKubeconfig := filepath.Join(home, ".kube", "config")
			
			if _, statErr := os.Stat(defaultKubeconfig); statErr == nil {
				config, err = clientcmd.BuildConfigFromFlags("", defaultKubeconfig)
				if err != nil {
					return nil, fmt.Errorf("load default kubeconfig: %w", err)
				}
			} else {
				return nil, fmt.Errorf("in-cluster config failed and no kubeconfig found: %w", err)
			}
		}
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}

	return client, nil
}

// Start begins watching pod events.
func (w *Watcher) Start(ctx context.Context) error {
	w.logger.Info("starting pod watcher")

	// Start the informer
	go w.informer.Run(w.stopCh)

	// Wait for cache sync
	if !cache.WaitForCacheSync(ctx.Done(), w.informer.HasSynced) {
		return fmt.Errorf("k8s/watcher: cache sync timeout")
	}

	w.logger.Info("pod watcher cache synced")

	// Wait for context cancellation
	<-ctx.Done()
	return w.Stop()
}

// Stop stops the watcher. Safe to call multiple times — subsequent calls are no-ops.
func (w *Watcher) Stop() error {
	w.logger.Info("stopping pod watcher")
	w.stopOnce.Do(func() { close(w.stopCh) })
	return nil
}

// GetPodInfo returns Kubernetes metadata for a given container ID.
func (w *Watcher) GetPodInfo(containerID string) (*PodInfo, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	info, ok := w.podCache[normalizeContainerID(containerID)]
	return info, ok
}

// GetPodInfoByPID returns Kubernetes metadata for a process by PID.
// It reads the container ID from /proc/<pid>/cgroup.
func (w *Watcher) GetPodInfoByPID(pid uint32) (*PodInfo, bool) {
	containerID, err := w.getContainerIDFromPID(pid)
	if err != nil {
		return nil, false
	}
	return w.GetPodInfo(containerID)
}

// getContainerIDFromPID reads container ID from cgroup.
func (w *Watcher) getContainerIDFromPID(pid uint32) (string, error) {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "", fmt.Errorf("read cgroup: %w", err)
	}

	return extractContainerID(string(data))
}

// extractContainerID extracts container ID from cgroup content.
func extractContainerID(cgroupContent string) (string, error) {
	lines := strings.Split(cgroupContent, "\n")
	for _, line := range lines {
		// Look for containerd/cri-o format: .../cri-containerd-<container_id>.scope
		// or docker format: .../docker-<container_id>.scope
		parts := strings.Split(line, "/")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			// Remove prefixes and suffixes
			part = strings.TrimPrefix(part, "docker-")
			part = strings.TrimPrefix(part, "cri-containerd-")
			part = strings.TrimPrefix(part, "containerd-cri-")
			part = strings.TrimSuffix(part, ".scope")
			
			// Check if it looks like a container ID (64 hex chars)
			if len(part) == 64 {
				isHex := true
				for _, c := range part {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
						isHex = false
						break
					}
				}
				if isHex {
					return part, nil
				}
			}
		}
	}
	return "", fmt.Errorf("container ID not found in cgroup")
}

// normalizeContainerID normalizes container ID for cache lookup.
func normalizeContainerID(id string) string {
	id = strings.TrimPrefix(id, "docker://")
	id = strings.TrimPrefix(id, "containerd://")
	id = strings.TrimPrefix(id, "cri-o://")
	return strings.ToLower(id)
}

// onPodAdd handles pod addition events.
func (w *Watcher) onPodAdd(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		w.logger.Warn("unexpected object type in pod add", "type", fmt.Sprintf("%T", obj))
		return
	}

	w.logger.Debug("pod added", "name", pod.Name, "namespace", pod.Namespace)
	w.updatePodCache(pod)
}

// onPodUpdate handles pod update events.
func (w *Watcher) onPodUpdate(oldObj, newObj interface{}) {
	newPod, ok := newObj.(*corev1.Pod)
	if !ok {
		w.logger.Warn("unexpected object type in pod update", "type", fmt.Sprintf("%T", newObj))
		return
	}

	w.logger.Debug("pod updated", "name", newPod.Name, "namespace", newPod.Namespace)
	w.updatePodCache(newPod)
}

// onPodDelete handles pod deletion events.
func (w *Watcher) onPodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// Handle tombstone object
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			w.logger.Warn("unexpected object type in pod delete", "type", fmt.Sprintf("%T", obj))
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			w.logger.Warn("unexpected tombstone object type", "type", fmt.Sprintf("%T", tombstone.Obj))
			return
		}
	}

	w.logger.Debug("pod deleted", "name", pod.Name, "namespace", pod.Namespace)
	w.removePodFromCache(pod)
}

// updatePodCache updates the cache with pod information.
func (w *Watcher) updatePodCache(pod *corev1.Pod) {
	info := &PodInfo{
		Name:        pod.Name,
		Namespace:   pod.Namespace,
		UID:         string(pod.UID),
		Labels:      copyMap(pod.Labels),
		Annotations: copyMap(pod.Annotations),
		NodeName:    pod.Spec.NodeName,
	}

	// Extract container IDs
	for _, containerStatus := range pod.Status.ContainerStatuses {
		containerID := normalizeContainerID(containerStatus.ContainerID)
		if containerID != "" {
			info.ContainerIDs = append(info.ContainerIDs, containerID)
		}
	}
	for _, initStatus := range pod.Status.InitContainerStatuses {
		containerID := normalizeContainerID(initStatus.ContainerID)
		if containerID != "" {
			info.ContainerIDs = append(info.ContainerIDs, containerID)
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Index by each container ID
	for _, cid := range info.ContainerIDs {
		w.podCache[cid] = info
	}
}

// removePodFromCache removes pod information from the cache.
func (w *Watcher) removePodFromCache(pod *corev1.Pod) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Remove by container IDs from status
	for _, containerStatus := range pod.Status.ContainerStatuses {
		cid := normalizeContainerID(containerStatus.ContainerID)
		if cid != "" {
			delete(w.podCache, cid)
		}
	}
	for _, initStatus := range pod.Status.InitContainerStatuses {
		cid := normalizeContainerID(initStatus.ContainerID)
		if cid != "" {
			delete(w.podCache, cid)
		}
	}
}

// copyMap creates a shallow copy of a map.
func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// GetAllPods returns a snapshot of all cached pods.
func (w *Watcher) GetAllPods() []*PodInfo {
	w.mu.RLock()
	defer w.mu.RUnlock()

	seen := make(map[string]bool)
	result := make([]*PodInfo, 0)

	for _, info := range w.podCache {
		if !seen[info.UID] {
			seen[info.UID] = true
			result = append(result, info)
		}
	}

	return result
}
