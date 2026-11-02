package operator

import (
	"context"
	"fmt"
	"github.com/openshift/console-operator/pkg/console/subresource/consoleserver"
	deploymentsub "github.com/openshift/console-operator/pkg/console/subresource/deployment"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"

	"github.com/openshift/console-operator/pkg/api"
	"github.com/openshift/console-operator/pkg/console/errors"
	"github.com/openshift/console-operator/pkg/proxyconfig"
)

func (c *consoleOperator) SyncAuthProxyTrustedCAConfigMap(proxy *proxyconfig.Config) (string, error) {
	// We must always call SyncConfigMap, even when no proxy is configured,
	// because that actually ensures the ConfigMap gets removed when proxy is removed.
	destination := resourcesynccontroller.ResourceLocation{Namespace: api.TargetNamespace, Name: api.AuthProxyCAConfigMapName}
	source := resourcesynccontroller.ResourceLocation{}
	if proxy != nil && proxy.TrustedCAName != "" {
		sourceConfigMap, err := c.configNSConfigMapLister.ConfigMaps(api.OpenShiftConfigNamespace).Get(proxy.TrustedCAName)
		if apierrors.IsNotFound(err) {
			return "SourceNotFound", fmt.Errorf("authentication proxy trustedCA ConfigMap %s/%s not found", api.OpenShiftConfigNamespace, proxy.TrustedCAName)
		}
		if err != nil {
			return "FailedGetSource", fmt.Errorf("getting authentication proxy trustedCA ConfigMap %s/%s: %w", api.OpenShiftConfigNamespace, proxy.TrustedCAName, err)
		}
		if _, ok := sourceConfigMap.Data[api.AuthProxyCAFileName]; !ok {
			return "InvalidSource", fmt.Errorf("authentication proxy trustedCA ConfigMap %s/%s is missing required key %q", api.OpenShiftConfigNamespace, proxy.TrustedCAName, api.AuthProxyCAFileName)
		}
		source = resourcesynccontroller.ResourceLocation{Namespace: api.OpenShiftConfigNamespace, Name: proxy.TrustedCAName}
	}
	if err := c.resourceSyncer.SyncConfigMap(destination, source); err != nil {
		return "FailedResourceSyncUpdate", fmt.Errorf("registering authentication proxy CA sync: %w", err)
	}

	// We block further sync/deployment when the ConfigMap is not yet in place.
	// This is because Console required the volume and actually loads the bundle initially on startup,
	// then starts watching it. This is consistent with what other operators/operands do.
	if source.Name != "" {
		if _, err := c.targetNSConfigMapLister.ConfigMaps(destination.Namespace).Get(destination.Name); err != nil {
			if apierrors.IsNotFound(err) {
				return "AwaitingLocalConfigMapSync", errors.NewSyncError(fmt.Sprintf("waiting for authentication proxy CA ConfigMap %s/%s", destination.Namespace, destination.Name))
			}
			return "FailedGetLocalConfigMap", fmt.Errorf("getting authentication proxy CA ConfigMap %s/%s: %v", destination.Namespace, destination.Name, err)
		}
	}
	return "", nil
}

// syncAuthProxyCAMount stages only the CA mount, retaining the currently published
// Console configuration until the Deployment has replaced its old Pods.
func (c *consoleOperator) syncAuthProxyCAMount(ctx context.Context, proxy *proxyconfig.Config) (string, error) {
	if proxy == nil || proxy.TrustedCAName == "" {
		return "", nil
	}
	deployment, err := c.deploymentClient.Deployments(api.TargetNamespace).Get(ctx, api.OpenShiftConsoleDeploymentName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	} // Initial creation has no existing Pods to protect.
	if err != nil {
		return "FailedGetDeployment", err
	}
	updated := deployment.DeepCopy()
	spec := &updated.Spec.Template.Spec
	hasVolume, hasMount := false, false
	volume := corev1.Volume{Name: api.AuthProxyCAConfigMapName, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: api.AuthProxyCAConfigMapName}, Items: []corev1.KeyToPath{{Key: api.AuthProxyCAFileName, Path: api.AuthProxyCAFileName}}}}}
	volumeIndex := -1
	for i, existing := range spec.Volumes {
		if existing.Name == volume.Name {
			volumeIndex = i
			hasVolume = existing.ConfigMap != nil && existing.ConfigMap.Name == volume.Name
			if hasVolume && len(existing.ConfigMap.Items) > 0 {
				hasVolume = false
				for _, item := range existing.ConfigMap.Items {
					if item.Key == api.AuthProxyCAFileName && item.Path == api.AuthProxyCAFileName {
						hasVolume = true
					}
				}
			}
			break
		}
	}
	if !hasVolume {
		if volumeIndex < 0 {
			spec.Volumes = append(spec.Volumes, volume)
		} else {
			spec.Volumes[volumeIndex] = volume
		}
	}
	containerIndex := -1
	for i := range spec.Containers {
		if spec.Containers[i].Name == "console" {
			containerIndex = i
			break
		}
	}
	if containerIndex < 0 {
		return "InvalidDeployment", fmt.Errorf("Console Deployment has no console container")
	}
	mounts := &spec.Containers[containerIndex].VolumeMounts
	mountIndex := -1
	mount := corev1.VolumeMount{Name: api.AuthProxyCAConfigMapName, MountPath: api.AuthProxyCAMountDir, ReadOnly: true}
	for i, existing := range *mounts {
		if existing.Name == mount.Name {
			mountIndex = i
			hasMount = existing.MountPath == mount.MountPath && existing.SubPath == "" && existing.SubPathExpr == ""
			break
		}
	}
	if !hasMount {
		if mountIndex < 0 {
			*mounts = append(*mounts, mount)
		} else {
			(*mounts)[mountIndex] = mount
		}
	}
	if !hasVolume || !hasMount {
		if _, err := c.deploymentClient.Deployments(api.TargetNamespace).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
			return "FailedStageMount", err
		}
		return "AwaitingMountRollout", errors.NewSyncError("waiting for Console authentication proxy CA mount rollout")
	}
	// Once the CA path has been published, readiness must not prevent fixing
	// unrelated configuration that could itself be keeping Console unhealthy.
	current, err := c.configMapClient.ConfigMaps(api.TargetNamespace).Get(ctx, api.OpenShiftConsoleConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "FailedGetConsoleConfigMap", err
	}
	var config consoleserver.Config
	if err := yaml.Unmarshal([]byte(current.Data["console-config.yaml"]), &config); err == nil && config.Auth.Proxy != nil && config.Auth.Proxy.TrustedCAFilePath == api.AuthProxyCAMountDir+"/"+api.AuthProxyCAFileName {
		return "", nil
	}
	replicas := int32(deploymentsub.DefaultConsoleReplicas)
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}
	if deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.UpdatedReplicas != replicas || deployment.Status.Replicas != replicas || deployment.Status.AvailableReplicas < replicas {
		return "AwaitingMountRollout", errors.NewSyncError("waiting for Console authentication proxy CA mount rollout")
	}
	return "", nil
}
