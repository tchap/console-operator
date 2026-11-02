package operator

import (
	"bytes"
	"flag"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/console-operator/pkg/api"
	consoleerrors "github.com/openshift/console-operator/pkg/console/errors"
	secretsub "github.com/openshift/console-operator/pkg/console/subresource/secret"
	"github.com/openshift/console-operator/pkg/console/telemetry"
	"github.com/openshift/console-operator/pkg/proxyconfig"
)

// TestSyncAwaitsAuthProxyCABeforePublishingConfigMap verifies that sync_v400
// does not publish (or otherwise touch) the console-config ConfigMap or the
// Deployment while the auth proxy's trusted CA has not yet been copied into the
// target namespace -- i.e. SyncAuthProxyTrustedCAConfigMap gates SyncConfigMap,
// preserving whatever Console configuration was already in place.
func TestSyncAwaitsAuthProxyCABeforePublishingConfigMap(t *testing.T) {
	co, kubeClient, configs := newAuthProxyReconcileFixture(t, copiedCAPending)
	recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))

	err := co.handleSync(t.Context(), factory.NewSyncContext("test", recorder), configs)
	if err == nil {
		t.Fatal("expected an error while awaiting the auth proxy CA copy, got nil")
	}
	if !consoleerrors.IsSyncError(err) {
		t.Errorf("expected a retriable sync error, got: %v", err)
	}

	if _, getErr := kubeClient.CoreV1().ConfigMaps(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleConfigMapName, metav1.GetOptions{}); !apierrors.IsNotFound(getErr) {
		t.Errorf("expected console-config ConfigMap to not be published yet, error returned: %v", getErr)
	}
	if _, getErr := kubeClient.AppsV1().Deployments(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleDeploymentName, metav1.GetOptions{}); !apierrors.IsNotFound(getErr) {
		t.Errorf("expected console Deployment to not be created yet, error returned: %v", getErr)
	}
}

// TestSyncPublishesConfigMapAndDeploymentTogetherOnceAuthProxyCAIsPresent
// verifies that once the copied proxy CA is confirmed present, sync_v400
// publishes the console-config ConfigMap referencing the CA file and rolls out
// the Deployment with the matching volume/mount in the same reconcile.
func TestSyncPublishesConfigMapAndDeploymentTogetherOnceAuthProxyCAIsPresent(t *testing.T) {
	co, kubeClient, configs := newAuthProxyReconcileFixture(t, copiedCAPresent)
	recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))

	if err := co.handleSync(t.Context(), factory.NewSyncContext("test", recorder), configs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cm, err := kubeClient.CoreV1().ConfigMaps(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected console-config ConfigMap to be published: %v", err)
	}
	wantCAPath := api.AuthProxyCAMountDir + "/" + api.AuthProxyCAFileName
	referencesCA := false
	for _, data := range cm.Data {
		if strings.Contains(data, wantCAPath) {
			referencesCA = true
		}
	}
	if !referencesCA {
		t.Errorf("expected console-config ConfigMap to reference %q, got: %#v", wantCAPath, cm.Data)
	}

	dep, err := kubeClient.AppsV1().Deployments(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleDeploymentName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected console Deployment to be created: %v", err)
	}
	hasVolume := false
	for _, vol := range dep.Spec.Template.Spec.Volumes {
		if vol.Name == api.AuthProxyCAConfigMapName {
			hasVolume = true
		}
	}
	if !hasVolume {
		t.Errorf("expected Deployment to mount the auth proxy CA volume %q, got volumes: %#v", api.AuthProxyCAConfigMapName, dep.Spec.Template.Spec.Volumes)
	}
}

// newAuthProxyReconcileFixture builds a consoleOperator wired with the minimal
// set of fakes/listers needed to drive a full Managed-state sync_v400 reconcile
// for an OIDC console with an authProxy.trustedCA configured, parameterized by
// the readiness state of the copied proxy CA ConfigMap.
func newAuthProxyReconcileFixture(t *testing.T, caState copiedCAState) (*consoleOperator, *fake.Clientset, configSet) {
	t.Helper()

	const consoleURL = "https://console-openshift-console.apps.example.com"

	op := &operatorv1.Console{ObjectMeta: metav1.ObjectMeta{Name: api.ConfigResourceName}}
	op.Spec.ManagementState = operatorv1.Managed
	op.Spec.Ingress.ConsoleURL = consoleURL

	consoleConfig := &configv1.Console{
		ObjectMeta: metav1.ObjectMeta{Name: api.ConfigResourceName},
		Status:     configv1.ConsoleStatus{ConsoleURL: consoleURL},
	}

	authnConfig := &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{Name: api.ConfigResourceName},
		Spec: configv1.AuthenticationSpec{
			Type: configv1.AuthenticationTypeOIDC,
			OIDCProviders: []configv1.OIDCProvider{{
				Name: "test-oidc",
				Issuer: configv1.TokenIssuer{
					URL:       "https://idp.example.com",
					Audiences: []configv1.TokenAudience{"console"},
				},
				OIDCClients: []configv1.OIDCClientConfig{{
					ComponentNamespace: api.TargetNamespace,
					ComponentName:      api.OpenShiftConsoleName,
					ClientID:           "console-client",
				}},
			}},
		},
	}

	featureGate := &configv1.FeatureGate{ObjectMeta: metav1.ObjectMeta{Name: api.ConfigResourceName}}
	clusterVersion := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: api.VersionResourceName},
		Spec:       configv1.ClusterVersionSpec{ClusterID: "test-cluster-id"},
	}
	telemetryConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: api.OpenShiftConsoleOperatorNamespace, Name: telemetry.TelemetryConfigMapName},
	}
	oauthClientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: api.TargetNamespace, Name: secretsub.Stub().Name},
	}
	consoleServingCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: api.TargetNamespace, Name: api.ConsoleServingCertName},
	}

	mustAdd := func(indexer cache.Indexer, obj any) {
		if err := indexer.Add(obj); err != nil {
			t.Fatal(err)
		}
	}

	authnIndexer := newIndexer(cache.MetaNamespaceKeyFunc)
	mustAdd(authnIndexer, authnConfig)

	featureGateIndexer := newIndexer(cache.MetaNamespaceKeyFunc)
	mustAdd(featureGateIndexer, featureGate)

	clusterVersionIndexer := newIndexer(cache.MetaNamespaceKeyFunc)
	mustAdd(clusterVersionIndexer, clusterVersion)

	operatorNSConfigMapIndexer := newIndexer(cache.MetaNamespaceKeyFunc)
	mustAdd(operatorNSConfigMapIndexer, telemetryConfigMap)

	secretsIndexer := newIndexer(cache.MetaNamespaceKeyFunc)
	mustAdd(secretsIndexer, oauthClientSecret)
	mustAdd(secretsIndexer, consoleServingCertSecret)

	kubeClient := fake.NewClientset()

	co := &consoleOperator{
		operatorClient:             v1helpers.NewFakeOperatorClient(&op.Spec.OperatorSpec, &operatorv1.OperatorStatus{}, nil),
		authnConfigLister:          configlistersv1.NewAuthenticationLister(authnIndexer),
		featureGateLister:          configlistersv1.NewFeatureGateLister(featureGateIndexer),
		clusterVersionLister:       configlistersv1.NewClusterVersionLister(clusterVersionIndexer),
		operatorNSConfigMapLister:  corev1listers.NewConfigMapLister(operatorNSConfigMapIndexer),
		managedNSConfigMapLister:   corev1listers.NewConfigMapLister(newIndexer(cache.MetaNamespaceKeyFunc)),
		targetNSConfigMapLister:    destinationLister(t, caState, "auth proxy CA lookup failed"),
		configNSConfigMapLister:    sourceLister(t, sourceCAValid, "user-ca-bundle", "auth proxy trustedCA lookup failed"),
		nodeLister:                 corev1listers.NewNodeLister(newIndexer(cache.MetaNamespaceKeyFunc)),
		monitoringDeploymentLister: appsv1listers.NewDeploymentLister(newIndexer(cache.MetaNamespaceKeyFunc)),
		configNSSecretLister:       corev1listers.NewSecretLister(newIndexer(cache.MetaNamespaceKeyFunc)),
		secretsLister:              corev1listers.NewSecretLister(secretsIndexer),
		secretsClient:              kubeClient.CoreV1(),
		configMapClient:            kubeClient.CoreV1(),
		deploymentClient:           kubeClient.AppsV1(),
		resourceSyncer:             &recordingResourceSyncer{},
		authProxyResolver: stubProxyResolver{config: &proxyconfig.Config{
			TrustedCAName: "user-ca-bundle",
			HTTPProxy:     "http://proxy.example:3128",
		}},
		versionGetter: status.NewVersionGetter(),
	}
	co.trackables.isOLMDisabled = true
	// Pre-seed the telemetry org/account cache so GetTelemetryConfiguration takes
	// the cached-values path instead of making a real OCM subscription request.
	co.trackables.organizationID = "test-org"
	co.trackables.accountMail = "test@example.com"

	configs := configSet{
		Console:        consoleConfig,
		Operator:       op,
		Infrastructure: &configv1.Infrastructure{ObjectMeta: metav1.ObjectMeta{Name: api.ConfigResourceName}},
		Proxy:          &configv1.Proxy{ObjectMeta: metav1.ObjectMeta{Name: api.ConfigResourceName}},
		OAuth:          &configv1.OAuth{ObjectMeta: metav1.ObjectMeta{Name: api.ConfigResourceName}},
		Ingress:        &configv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: api.ConfigResourceName}},
	}

	return co, kubeClient, configs
}

// stubProxyResolver resolves a fixed component proxy configuration, bypassing
// the real GatedProxyResolver/ConsoleProxyResolver feature-gate plumbing.
type stubProxyResolver struct {
	config *proxyconfig.Config
}

func (s stubProxyResolver) ResolveProxy(*operatorv1.Console) (*proxyconfig.Config, error) {
	return s.config, nil
}

// Existing Pods must acquire the CA mount before the shared configuration can
// reference it, even when a later Secret lookup interrupts reconciliation.
func TestSyncStagesAuthProxyMountBeforePublishingConfig(t *testing.T) {
	for _, missingSecret := range []bool{false, true} {
		name := "successful reconcile"
		if missingSecret {
			name = "missing Secret after rollout"
		}
		t.Run(name, func(t *testing.T) {
			co, client, configs := newAuthProxyReconcileFixture(t, copiedCAPresent)
			co.authProxyResolver = stubProxyResolver{}
			recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))
			sync := func() error { return co.handleSync(t.Context(), factory.NewSyncContext("test", recorder), configs) }
			if err := sync(); err != nil {
				t.Fatal(err)
			}
			refreshAuthProxyConfigMapLister(t, co, client)
			original, err := client.CoreV1().ConfigMaps(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleConfigMapName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			co.authProxyResolver = stubProxyResolver{config: &proxyconfig.Config{TrustedCAName: "user-ca-bundle", HTTPSProxy: "https://proxy.example:3128"}}
			if missingSecret {
				// This lister deliberately lacks the OAuth client secret.
				indexer := newIndexer(cache.MetaNamespaceKeyFunc)
				indexer.Add(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: api.TargetNamespace, Name: api.ConsoleServingCertName}})
				co.secretsLister = corev1listers.NewSecretLister(indexer)
			}
			assertUnchanged := func() {
				t.Helper()
				actual, err := client.CoreV1().ConfigMaps(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleConfigMapName, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(original, actual) {
					t.Fatal("published new configuration before CA mount rollout completed")
				}
			}
			if err := sync(); !consoleerrors.IsSyncError(err) {
				t.Fatalf("expected mount rollout wait, got %v", err)
			}
			assertUnchanged()
			dep, err := client.AppsV1().Deployments(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleDeploymentName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			// Fake clients do not increment Deployment generations.
			dep.Generation = 2
			dep.Status.ObservedGeneration = 1
			if _, err := client.AppsV1().Deployments(api.TargetNamespace).Update(t.Context(), dep, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := sync(); !consoleerrors.IsSyncError(err) {
				t.Fatalf("expected incomplete rollout wait, got %v", err)
			}
			assertUnchanged()
			// The new template alone is insufficient: old replicas must be gone
			// and all replacement replicas must be available.
			for _, rollout := range []struct{ updated, total, available int32 }{
				{1, 2, 2}, // Old Pods are still counted.
				{2, 3, 2}, // A surge replica is still present.
				{2, 2, 1}, // Replacement Pods are not all available.
			} {
				dep.Status.ObservedGeneration = dep.Generation
				dep.Status.UpdatedReplicas = rollout.updated
				dep.Status.Replicas = rollout.total
				dep.Status.AvailableReplicas = rollout.available
				if _, err := client.AppsV1().Deployments(api.TargetNamespace).UpdateStatus(t.Context(), dep, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				if err := sync(); !consoleerrors.IsSyncError(err) {
					t.Fatalf("expected rollout wait for %+v, got %v", rollout, err)
				}
				assertUnchanged()
			}
			dep.Status.ObservedGeneration = dep.Generation
			dep.Status.UpdatedReplicas = *dep.Spec.Replicas
			dep.Status.Replicas = *dep.Spec.Replicas
			dep.Status.AvailableReplicas = *dep.Spec.Replicas
			if _, err := client.AppsV1().Deployments(api.TargetNamespace).UpdateStatus(t.Context(), dep, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			err = sync()
			if missingSecret && !apierrors.IsNotFound(err) {
				t.Fatalf("expected missing Secret, got %v", err)
			}
			if !missingSecret && err != nil {
				t.Fatal(err)
			}
			cm, err := client.CoreV1().ConfigMaps(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleConfigMapName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(cm.Data["console-config.yaml"], api.AuthProxyCAMountDir+"/"+api.AuthProxyCAFileName) {
				t.Fatal("CA reference not published after mount rollout")
			}
			dep, err = client.AppsV1().Deployments(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleDeploymentName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			hasMount := false
			for _, mount := range dep.Spec.Template.Spec.Containers[0].VolumeMounts {
				if mount.Name == api.AuthProxyCAConfigMapName && mount.MountPath == api.AuthProxyCAMountDir {
					hasMount = true
				}
			}
			if !hasMount {
				t.Fatal("published CA path without a Deployment mount")
			}
		})
	}
}

func TestSyncConfigMapDoesNotLogProxyCredentials(t *testing.T) {
	for _, verbosity := range []string{"2", "4"} {
		t.Run("verbosity="+verbosity, func(t *testing.T) {
			co, client, configs := newAuthProxyReconcileFixture(t, copiedCAPresent)
			co.authProxyResolver = stubProxyResolver{}
			recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))
			sync := func() error { return co.handleSync(t.Context(), factory.NewSyncContext("test", recorder), configs) }
			if err := sync(); err != nil {
				t.Fatal(err)
			}
			refreshAuthProxyConfigMapLister(t, co, client)
			state := klog.CaptureState()
			defer state.Restore()
			flags := flag.NewFlagSet("logging", flag.ContinueOnError)
			klog.InitFlags(flags)
			if err := flags.Set("v", verbosity); err != nil {
				t.Fatal(err)
			}
			klog.LogToStderr(false)
			var logs bytes.Buffer
			klog.SetOutput(&logs)
			co.authProxyResolver = stubProxyResolver{config: &proxyconfig.Config{HTTPProxy: "http://review-user:review-password@review-tail@proxy.example:3128"}}
			if err := sync(); err != nil {
				t.Fatal(err)
			}
			klog.Flush()
			cm, err := client.CoreV1().ConfigMaps(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleConfigMapName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(cm.Data["console-config.yaml"], "review-password") {
				t.Fatal("credentials were not persisted to Console configuration")
			}
			for _, credential := range []string{"review-user", "review-password", "review-tail"} {
				if strings.Contains(logs.String(), credential) {
					t.Fatalf("proxy credential %q leaked in logs", credential)
				}
			}
			if verbosity == "4" && !strings.Contains(logs.String(), "new console config yaml") {
				t.Fatal("expected configuration logging path to be exercised")
			}
		})
	}
}

// Model the informer observing ConfigMaps created by the initial reconcile.
func refreshAuthProxyConfigMapLister(t *testing.T, co *consoleOperator, client *fake.Clientset) {
	t.Helper()
	existing, err := co.targetNSConfigMapLister.List(labels.Everything())
	if err != nil {
		t.Fatal(err)
	}
	indexer := newIndexer(cache.MetaNamespaceKeyFunc)
	for _, cm := range existing {
		if err := indexer.Add(cm); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := client.CoreV1().ConfigMaps(api.TargetNamespace).List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range actual.Items {
		if err := indexer.Add(&actual.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
	co.targetNSConfigMapLister = corev1listers.NewConfigMapLister(indexer)
}

func TestSyncAllowsConfigRepairWithAuthProxyMount(t *testing.T) {
	co, client, configs := newAuthProxyReconcileFixture(t, copiedCAPresent)
	recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))
	sync := func() error { return co.handleSync(t.Context(), factory.NewSyncContext("test", recorder), configs) }
	if err := sync(); err != nil {
		t.Fatal(err)
	}
	refreshAuthProxyConfigMapLister(t, co, client)
	// The fake Deployment has zero available replicas. An already-established CA
	// mount must not block configuration updates that may restore availability.
	co.authProxyResolver = stubProxyResolver{config: &proxyconfig.Config{TrustedCAName: "user-ca-bundle", HTTPProxy: "http://repaired-proxy.example:3128"}}
	if err := sync(); err != nil {
		t.Fatalf("configuration repair was blocked: %v", err)
	}
	cm, err := client.CoreV1().ConfigMaps(api.TargetNamespace).Get(t.Context(), api.OpenShiftConsoleConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cm.Data["console-config.yaml"], "repaired-proxy.example") {
		t.Fatal("configuration repair was not published")
	}
}
