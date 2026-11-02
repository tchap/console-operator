package operator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v2"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"

	"github.com/openshift/console-operator/pkg/api"
	"github.com/openshift/console-operator/pkg/console/errors"
	"github.com/openshift/console-operator/pkg/console/subresource/consoleserver"
	deploymentsub "github.com/openshift/console-operator/pkg/console/subresource/deployment"
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

// syncAuthProxyCAMount gives replacement Pods the desired configuration together
// with its CA mount, while old Pods retain the shared configuration. Staging must
// also accept later repairs before waiting for rollout progress.
func (c *consoleOperator) syncAuthProxyCAMount(ctx context.Context, proxy *proxyconfig.Config, requiredConfig *corev1.ConfigMap, requiredDeployment *appsv1.Deployment, recorder events.Recorder) (string, error) {
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
	current, err := c.configMapClient.ConfigMaps(api.TargetNamespace).Get(ctx, api.OpenShiftConsoleConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "FailedGetConsoleConfigMap", err
	}
	var config consoleserver.Config
	publishedCA := yaml.Unmarshal([]byte(current.Data["console-config.yaml"]), &config) == nil && config.Auth.Proxy != nil && config.Auth.Proxy.TrustedCAFilePath == api.AuthProxyCAMountDir+"/"+api.AuthProxyCAFileName
	if publishedCA {
		return "", nil
	}
	updated := deployment.DeepCopy()
	updated.Spec = *requiredDeployment.Spec.DeepCopy()
	spec := &updated.Spec.Template.Spec
	// Only new Pods consume this ConfigMap. Publishing a repair here cannot
	// expose the CA path to old Pods that do not have the CA volume.
	stagingConfig := requiredConfig.DeepCopy()
	stagingConfig.Name = api.AuthProxyStagingConfigMapName
	if _, _, err := c.applyConsoleConfigMap(ctx, recorder, stagingConfig); err != nil {
		return "FailedStageConfig", err
	}
	configVolume := -1
	for i := range spec.Volumes {
		if spec.Volumes[i].Name == api.OpenShiftConsoleConfigMapName && spec.Volumes[i].ConfigMap != nil {
			configVolume = i
			break
		}
	}
	if configVolume < 0 {
		return "InvalidDeployment", fmt.Errorf("Console Deployment has no configuration volume")
	}
	staged := false
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.Name == api.OpenShiftConsoleConfigMapName && volume.ConfigMap != nil && volume.ConfigMap.Name == api.AuthProxyStagingConfigMapName {
			staged = true
		}
	}
	spec.Volumes[configVolume].ConfigMap.Name = api.AuthProxyStagingConfigMapName
	const configHashAnnotation = "console.openshift.io/auth-proxy-config-hash"
	stagingData, err := json.Marshal(struct {
		Config map[string]string
		Spec   appsv1.DeploymentSpec
	}{stagingConfig.Data, updated.Spec})
	if err != nil {
		return "FailedStageConfig", err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(stagingData))
	previousHash := deployment.Spec.Template.Annotations[configHashAnnotation]
	if updated.Spec.Template.Annotations == nil {
		updated.Spec.Template.Annotations = map[string]string{}
	}
	updated.Spec.Template.Annotations[configHashAnnotation] = hash
	if !staged || previousHash != hash {
		if _, err := c.deploymentClient.Deployments(api.TargetNamespace).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
			return "FailedStageMount", err
		}
		return "AwaitingMountRollout", errors.NewSyncError("waiting for Console authentication proxy CA mount rollout")
	}
	if !authProxyMountRolloutComplete(deployment) {
		return "AwaitingMountRollout", errors.NewSyncError("waiting for Console authentication proxy CA mount rollout")
	}
	return "", nil
}

// Mount safety depends on replacing old Pod templates, not on OIDC readiness.
func authProxyMountRolloutComplete(deployment *appsv1.Deployment) bool {
	replicas := int32(deploymentsub.DefaultConsoleReplicas)
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}
	return deployment.Status.ObservedGeneration >= deployment.Generation && deployment.Status.UpdatedReplicas == replicas && deployment.Status.Replicas == replicas
}

// Keep staging configuration until no remaining Pod uses that volume source.
func (c *consoleOperator) cleanupAuthProxyStagingConfigMap(ctx context.Context, deployment *appsv1.Deployment) error {
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == api.AuthProxyStagingConfigMapName {
			return nil
		}
	}
	if !authProxyMountRolloutComplete(deployment) {
		return nil
	}
	err := c.configMapClient.ConfigMaps(api.TargetNamespace).Delete(ctx, api.AuthProxyStagingConfigMapName, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
