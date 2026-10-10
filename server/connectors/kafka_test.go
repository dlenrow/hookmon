package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/IBM/sarama"
	"github.com/IBM/sarama/mocks"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// TestKafka_ProducesBatch: each event of a batch becomes one message on
// the topic, JSON-encoded, keyed by host ID.
func TestKafka_ProducesBatch(t *testing.T) {
	cfg := mocks.NewTestConfig()
	cfg.Producer.Return.Successes = true
	p := mocks.NewSyncProducer(t, cfg)
	batch := siemBatch(2)
	for _, want := range batch {
		want := want
		p.ExpectSendMessageWithMessageCheckerFunctionAndSucceed(func(m *sarama.ProducerMessage) error {
			if m.Topic != "hookmon-alerts" {
				t.Errorf("topic %q", m.Topic)
			}
			key, _ := m.Key.Encode()
			if string(key) != want.HostID {
				t.Errorf("key %q, want host ID %q", key, want.HostID)
			}
			val, _ := m.Value.Encode()
			var got event.HookEvent
			if err := json.Unmarshal(val, &got); err != nil {
				return err
			}
			if got.ID != want.ID || got.BPFDetail == nil || got.BPFDetail.ProgName != "hello_count" {
				t.Errorf("value %s", val)
			}
			return nil
		})
	}
	k := newKafkaConnector(p, "hookmon-alerts", zap.NewNop())
	if err := k.Send(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := k.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// TestKafka_FailureIsRetryable: a produce error goes back to the worker as
// retryable.
func TestKafka_FailureIsRetryable(t *testing.T) {
	cfg := mocks.NewTestConfig()
	cfg.Producer.Return.Successes = true
	p := mocks.NewSyncProducer(t, cfg)
	p.ExpectSendMessageAndFail(sarama.ErrNotLeaderForPartition)
	k := newKafkaConnector(p, "t", zap.NewNop())
	err := k.Send(context.Background(), siemBatch(1))
	if err == nil || !isRetryable(err) || !errors.Is(err, sarama.ErrNotLeaderForPartition) {
		t.Errorf("Send: %v", err)
	}
	k.Close()
}
