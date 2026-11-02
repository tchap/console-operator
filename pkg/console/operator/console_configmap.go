package operator

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

// applyConsoleConfigMap applies Console configuration without logging its data.
// The generic resourceapply helper logs raw update diffs, which may contain proxy
// credentials. This ConfigMap has no injected CA data to preserve.
func (c *consoleOperator) applyConsoleConfigMap(ctx context.Context, recorder events.Recorder, required *corev1.ConfigMap) (*corev1.ConfigMap, bool, error) {
	client := c.configMapClient.ConfigMaps(required.Namespace)
	existing, err := client.Get(ctx, required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		clean := resourcemerge.WithCleanLabelsAndAnnotations(required.DeepCopy()).(*corev1.ConfigMap)
		actual, err := client.Create(ctx, clean, metav1.CreateOptions{})
		resourcehelper.ReportCreateEvent(recorder, clean, err)
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}
	updated := existing.DeepCopy()
	modified := false
	resourcemerge.EnsureObjectMeta(&modified, &updated.ObjectMeta, required.ObjectMeta)
	if !modified && equality.Semantic.DeepEqual(existing.Data, required.Data) && equality.Semantic.DeepEqual(existing.BinaryData, required.BinaryData) {
		return existing, false, nil
	}
	updated.Data = required.Data
	updated.BinaryData = required.BinaryData
	actual, err := client.Update(ctx, updated, metav1.UpdateOptions{})
	resourcehelper.ReportUpdateEvent(recorder, required, err)
	return actual, true, err
}
