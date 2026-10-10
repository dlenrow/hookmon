package connectors

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/pkg/event"
)

func TestConfigValidate(t *testing.T) {
	good := []Config{
		{},
		{Syslog: &SyslogConfig{Address: "siem:514"}},
		{Syslog: &SyslogConfig{Address: "siem:514", Protocol: "UDP", Facility: "LOCAL4", Delivery: Delivery{MinSeverity: "info"}}},
		{Syslog: &SyslogConfig{Address: "[::1]:6514", Framing: "lf"}},
		{Splunk: &SplunkConfig{URL: "https://splunk:8088/services/collector/event", Token: "t"}},
		{Elastic: &ElasticConfig{URL: "https://es:9200", APIKey: "k", ILM: ElasticILMConfig{DeleteAfter: "720h"}}},
		{Elastic: &ElasticConfig{URL: "http://es:9200", Username: "u", Password: "p", IndexPrefix: "sec-hookmon"}},
		{Webhook: &WebhookConfig{URL: "https://hooks.example/x", Headers: map[string]string{"Authorization": "Bearer x"},
			Delivery: Delivery{BatchSize: 50, FlushInterval: 2 * time.Second, QueueSize: 10}}},
		{Kafka: &KafkaConfig{Brokers: []string{"k1:9092", "k2:9092"}, Topic: "hookmon"}},
	}
	for i, c := range good {
		if err := c.Validate(); err != nil {
			t.Errorf("good %d: %v", i, err)
		}
	}

	bad := map[string]Config{
		"syslog no port":         {Syslog: &SyslogConfig{Address: "siem"}},
		"syslog protocol":        {Syslog: &SyslogConfig{Address: "siem:514", Protocol: "tls"}},
		"syslog framing":         {Syslog: &SyslogConfig{Address: "siem:514", Framing: "nul"}},
		"syslog udp framing":     {Syslog: &SyslogConfig{Address: "siem:514", Protocol: "udp", Framing: "lf"}},
		"syslog facility":        {Syslog: &SyslogConfig{Address: "siem:514", Facility: "local9"}},
		"min severity":           {Syslog: &SyslogConfig{Address: "siem:514", Delivery: Delivery{MinSeverity: "HIGH"}}},
		"negative queue":         {Syslog: &SyslogConfig{Address: "siem:514", Delivery: Delivery{QueueSize: -1}}},
		"splunk no token":        {Splunk: &SplunkConfig{URL: "https://splunk:8088"}},
		"splunk no url":          {Splunk: &SplunkConfig{Token: "t"}},
		"splunk relative url":    {Splunk: &SplunkConfig{URL: "splunk:8088/x", Token: "t"}},
		"elastic half basic":     {Elastic: &ElasticConfig{URL: "https://es:9200", Username: "u"}},
		"elastic both auth":      {Elastic: &ElasticConfig{URL: "https://es:9200", Username: "u", Password: "p", APIKey: "k"}},
		"elastic upper prefix":   {Elastic: &ElasticConfig{URL: "https://es:9200", IndexPrefix: "HookMon"}},
		"elastic delete_after":   {Elastic: &ElasticConfig{URL: "https://es:9200", ILM: ElasticILMConfig{DeleteAfter: "3 months"}}},
		"webhook ftp":            {Webhook: &WebhookConfig{URL: "ftp://x/y"}},
		"webhook header":         {Webhook: &WebhookConfig{URL: "https://x/y", Headers: map[string]string{"Bad Name": "v"}}},
		"kafka no brokers":       {Kafka: &KafkaConfig{Topic: "t"}},
		"kafka broker no port":   {Kafka: &KafkaConfig{Brokers: []string{"k1"}, Topic: "t"}},
		"kafka no topic":         {Kafka: &KafkaConfig{Brokers: []string{"k1:9092"}}},
		"webhook negative batch": {Webhook: &WebhookConfig{URL: "https://x/y", Delivery: Delivery{BatchSize: -2}}},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDeliveryDefaults(t *testing.T) {
	d := Delivery{}.withDefaults(100)
	if d.MinSeverity != event.SeverityAlert || d.QueueSize != 1024 || d.BatchSize != 100 || d.FlushInterval != time.Second {
		t.Errorf("defaults %+v", d)
	}
	d = Delivery{MinSeverity: "warn", QueueSize: 5, BatchSize: 2, FlushInterval: time.Minute}.withDefaults(100)
	if d.MinSeverity != event.SeverityWarn || d.QueueSize != 5 || d.BatchSize != 2 || d.FlushInterval != time.Minute {
		t.Errorf("explicit %+v", d)
	}
}

// TestNew_InitFailureClosesAndFails: when one connector cannot start, New
// fails and closes the ones it already built.
func TestNew_InitFailureClosesAndFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()

	cfg := Config{
		Syslog: &SyslogConfig{Address: ln.Addr().String()},
		Kafka:  &KafkaConfig{Brokers: []string{deadAddr}, Topic: "t"},
	}
	_, err = New(context.Background(), cfg, nil, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "connectors.kafka") {
		t.Fatalf("New with an unreachable broker: %v", err)
	}
	// The syslog connection New opened was closed.
	select {
	case c := <-accepted:
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Error("syslog connection still open after New failed")
		}
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("syslog never connected")
	}
}
