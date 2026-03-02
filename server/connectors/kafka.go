package connectors

import (
	"encoding/json"
	"fmt"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

// KafkaConnector produces events to a Kafka topic.
type KafkaConnector struct {
	producer sarama.SyncProducer
	topic    string
	logger   *zap.Logger
}

// NewKafkaConnector creates a connector that publishes JSON events to the
// specified Kafka topic. It connects synchronously so that Send returns only
// after the broker has acknowledged the message.
func NewKafkaConnector(brokers []string, topic string, logger *zap.Logger) (*KafkaConnector, error) {
	cfg := sarama.NewConfig()
	cfg.Producer.Return.Successes = true
	cfg.Producer.RequiredAcks = sarama.WaitForAll
	cfg.Producer.Retry.Max = 3

	producer, err := sarama.NewSyncProducer(brokers, cfg)
	if err != nil {
		return nil, fmt.Errorf("kafka new producer: %w", err)
	}

	logger.Info("kafka connector established",
		zap.Strings("brokers", brokers),
		zap.String("topic", topic),
	)

	return &KafkaConnector{
		producer: producer,
		topic:    topic,
		logger:   logger,
	}, nil
}

// Name returns the connector identifier.
func (k *KafkaConnector) Name() string { return "kafka" }

// Send serialises the event as JSON and produces it to the Kafka topic. The
// event ID is used as the message key so that events for the same detection
// are routed to the same partition.
func (k *KafkaConnector) Send(evt *event.HookEvent) error {
	value, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("kafka marshal: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.topic,
		Key:   sarama.StringEncoder(evt.ID),
		Value: sarama.ByteEncoder(value),
	}

	partition, offset, err := k.producer.SendMessage(msg)
	if err != nil {
		k.logger.Error("kafka produce failed",
			zap.String("event_id", evt.ID),
			zap.Error(err),
		)
		return fmt.Errorf("kafka produce: %w", err)
	}

	k.logger.Debug("kafka event produced",
		zap.String("event_id", evt.ID),
		zap.Int32("partition", partition),
		zap.Int64("offset", offset),
	)

	return nil
}

// Close shuts down the Kafka producer, flushing any pending messages.
func (k *KafkaConnector) Close() error {
	if k.producer != nil {
		return k.producer.Close()
	}
	return nil
}
