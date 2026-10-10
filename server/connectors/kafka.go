package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// KafkaConnector produces events to a Kafka topic as JSON, keyed by host
// ID so each host's events stay in order on one partition.
type KafkaConnector struct {
	producer sarama.SyncProducer
	topic    string
	logger   *zap.Logger
}

// NewKafkaConnector connects a synchronous producer to the brokers, so a
// broker that cannot be reached fails startup. Send returns only after
// every broker in sync has acknowledged the batch.
func NewKafkaConnector(cfg KafkaConfig, logger *zap.Logger) (*KafkaConnector, error) {
	sc := sarama.NewConfig()
	sc.ClientID = "hookmon-server"
	sc.Producer.Return.Successes = true
	sc.Producer.RequiredAcks = sarama.WaitForAll
	sc.Producer.Retry.Max = 3
	sc.Net.DialTimeout = 10 * time.Second
	sc.Metadata.Retry.Max = 1

	producer, err := sarama.NewSyncProducer(cfg.Brokers, sc)
	if err != nil {
		return nil, fmt.Errorf("kafka producer for %v: %w", cfg.Brokers, err)
	}
	logger.Info("kafka connector connected", zap.Strings("brokers", cfg.Brokers), zap.String("topic", cfg.Topic))
	return newKafkaConnector(producer, cfg.Topic, logger), nil
}

func newKafkaConnector(p sarama.SyncProducer, topic string, logger *zap.Logger) *KafkaConnector {
	return &KafkaConnector{producer: p, topic: topic, logger: logger}
}

// Name returns the connector identifier.
func (k *KafkaConnector) Name() string { return "kafka" }

// Send produces the batch. The producer has already retried by the time it
// fails, but a failure is still marked retryable, so the worker tries the
// batch again after a backoff (a broker failover can take longer than the
// producer's own retries).
func (k *KafkaConnector) Send(ctx context.Context, batch []*event.HookEvent) error {
	msgs := make([]*sarama.ProducerMessage, 0, len(batch))
	for _, evt := range batch {
		value, err := json.Marshal(evt)
		if err != nil {
			return fmt.Errorf("kafka marshal event %s: %w", evt.ID, err)
		}
		msgs = append(msgs, &sarama.ProducerMessage{
			Topic: k.topic,
			Key:   sarama.StringEncoder(evt.HostID),
			Value: sarama.ByteEncoder(value),
		})
	}
	if err := k.producer.SendMessages(msgs); err != nil {
		return retryable(fmt.Errorf("kafka produce: %w", err))
	}
	return nil
}

// Close shuts down the producer.
func (k *KafkaConnector) Close() error {
	return k.producer.Close()
}
