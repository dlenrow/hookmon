package connectors

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
)

// Config is the connectors section of the server config file. A connector
// runs only when its block is present. See deploy/server.example.yaml.
type Config struct {
	Syslog  *SyslogConfig  `yaml:"syslog"`
	Splunk  *SplunkConfig  `yaml:"splunk"`
	Elastic *ElasticConfig `yaml:"elasticsearch"`
	Webhook *WebhookConfig `yaml:"webhook"`
	Kafka   *KafkaConfig   `yaml:"kafka"`
}

// Delivery holds the settings every connector has.
type Delivery struct {
	// MinSeverity is the lowest severity the connector receives. ALERT (the
	// default) or CRITICAL makes it an alert connector: it gets events at
	// or above that severity that no allowlist entry allowed, with repeats
	// of the same alert (same host, event type, binary and subject) within
	// 5 minutes dropped, plus AGENT_OFFLINE. INFO or WARN makes it an event
	// feed: it gets every stored event at or above that severity, allowed
	// or not, repeats included, plus AGENT_OFFLINE.
	MinSeverity event.Severity `yaml:"min_severity"`
	// QueueSize bounds the events waiting for this connector. When it is
	// full, new events for the connector are dropped and counted.
	// Default 1024.
	QueueSize int `yaml:"queue_size"`
	// BatchSize is the most events sent in one request. Defaults: 1 for
	// syslog and webhook, 100 for Splunk, Elasticsearch and Kafka.
	BatchSize int `yaml:"batch_size"`
	// FlushInterval is the longest a partial batch waits for more events.
	// Default 1s.
	FlushInterval time.Duration `yaml:"flush_interval"`
}

const (
	defaultQueueSize     = 1024
	defaultFlushInterval = time.Second
)

// withDefaults fills unset delivery settings.
func (d Delivery) withDefaults(batchSize int) Delivery {
	if d.MinSeverity == "" {
		d.MinSeverity = event.SeverityAlert
	}
	d.MinSeverity = event.Severity(strings.ToUpper(string(d.MinSeverity)))
	if d.QueueSize == 0 {
		d.QueueSize = defaultQueueSize
	}
	if d.BatchSize == 0 {
		d.BatchSize = batchSize
	}
	if d.FlushInterval == 0 {
		d.FlushInterval = defaultFlushInterval
	}
	return d
}

func (d Delivery) validate() error {
	if d.MinSeverity != "" && severityRank(event.Severity(strings.ToUpper(string(d.MinSeverity)))) == 0 {
		return fmt.Errorf("min_severity %q: must be INFO, WARN, ALERT or CRITICAL", d.MinSeverity)
	}
	if d.QueueSize < 0 || d.BatchSize < 0 || d.FlushInterval < 0 {
		return errors.New("queue_size, batch_size and flush_interval must not be negative")
	}
	return nil
}

// SyslogConfig sends RFC 5424 syslog messages carrying CEF.
type SyslogConfig struct {
	// Address is the receiver's host:port.
	Address string `yaml:"address"`
	// Protocol is tcp (the default) or udp.
	Protocol string `yaml:"protocol"`
	// Framing is how messages are delimited on TCP: octet-counting (the
	// default; RFC 6587 section 3.4.1) or lf (a newline after each
	// message). UDP sends one message per datagram and takes no framing.
	Framing string `yaml:"framing"`
	// Facility is the syslog facility name: kern, user, mail, daemon, auth,
	// syslog, lpr, news, uucp, cron, authpriv, ftp, or local0 to local7.
	// Default local0.
	Facility string `yaml:"facility"`

	Delivery `yaml:",inline"`
}

// SplunkConfig sends events to a Splunk HTTP Event Collector.
type SplunkConfig struct {
	// URL is the full HEC endpoint, for example
	// https://splunk.example.com:8088/services/collector/event.
	URL string `yaml:"url"`
	// Token is the HEC token, sent as "Authorization: Splunk <token>".
	Token string `yaml:"token"`
	// Index is the Splunk index. Empty uses the token's default index.
	Index string `yaml:"index"`
	// SourceType defaults to hookmon:event.
	SourceType string `yaml:"source_type"`
	// CAFile verifies the HEC certificate when it is not signed by a CA the
	// system trusts.
	CAFile string `yaml:"ca_file"`

	Delivery `yaml:",inline"`
}

// ElasticConfig sends events to Elasticsearch with the _bulk API, into one
// index per day.
type ElasticConfig struct {
	// URL is the cluster's base URL, for example https://es.example.com:9200.
	URL string `yaml:"url"`
	// IndexPrefix names the daily indices: <prefix>-YYYY.MM.DD, by the
	// event's UTC date. Default hookmon-events.
	IndexPrefix string `yaml:"index_prefix"`
	// Username and Password are for HTTP basic authentication. APIKey is
	// the base64 "id:key" value Elasticsearch returns when an API key is
	// created, sent as "Authorization: ApiKey <key>". Set one or neither.
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	APIKey   string `yaml:"api_key"`
	// CAFile verifies the cluster's certificate when it is not signed by a
	// CA the system trusts.
	CAFile string `yaml:"ca_file"`
	// ILM is the index lifecycle setup.
	ILM ElasticILMConfig `yaml:"ilm"`

	Delivery `yaml:",inline"`
}

// ElasticILMConfig controls the index lifecycle policy and index template
// the connector installs at startup.
type ElasticILMConfig struct {
	// Setup installs (or updates) the ILM policy and an index template
	// that applies it to <index_prefix>-*. Default true. Set false when
	// the policy and template are managed elsewhere, or on OpenSearch,
	// which has ISM instead of ILM.
	Setup *bool `yaml:"setup"`
	// Policy is the ILM policy and index template name. Default
	// hookmon-events.
	Policy string `yaml:"policy"`
	// DeleteAfter is how long after its creation a daily index is deleted,
	// in Elasticsearch time units (for example 90d or 720h). Default 90d.
	DeleteAfter string `yaml:"delete_after"`
}

// WebhookConfig POSTs events as JSON to any URL.
type WebhookConfig struct {
	URL string `yaml:"url"`
	// Headers are added to every request, for example an Authorization
	// header.
	Headers map[string]string `yaml:"headers"`
	// CAFile verifies the receiver's certificate when it is not signed by a
	// CA the system trusts.
	CAFile string `yaml:"ca_file"`

	// With batch_size 1 (the default) each POST carries one event as a
	// JSON object; with a larger batch_size each POST carries a JSON array
	// of up to batch_size events.
	Delivery `yaml:",inline"`
}

// KafkaConfig produces events to a Kafka topic.
type KafkaConfig struct {
	Brokers []string `yaml:"brokers"`
	Topic   string   `yaml:"topic"`

	Delivery `yaml:",inline"`
}

// Validate checks the settings without connecting to anything. The server
// runs it when it loads its config file, so a mistake fails startup.
func (c *Config) Validate() error {
	if s := c.Syslog; s != nil {
		if err := s.validate(); err != nil {
			return fmt.Errorf("connectors.syslog: %w", err)
		}
	}
	if s := c.Splunk; s != nil {
		if err := checkURL(s.URL); err != nil {
			return fmt.Errorf("connectors.splunk: %w", err)
		}
		if s.Token == "" {
			return errors.New("connectors.splunk: token is required")
		}
		if err := s.Delivery.validate(); err != nil {
			return fmt.Errorf("connectors.splunk: %w", err)
		}
	}
	if e := c.Elastic; e != nil {
		if err := e.validate(); err != nil {
			return fmt.Errorf("connectors.elasticsearch: %w", err)
		}
	}
	if w := c.Webhook; w != nil {
		if err := checkURL(w.URL); err != nil {
			return fmt.Errorf("connectors.webhook: %w", err)
		}
		for k := range w.Headers {
			if k == "" || strings.ContainsAny(k, " :\r\n") {
				return fmt.Errorf("connectors.webhook: invalid header name %q", k)
			}
		}
		if err := w.Delivery.validate(); err != nil {
			return fmt.Errorf("connectors.webhook: %w", err)
		}
	}
	if k := c.Kafka; k != nil {
		if len(k.Brokers) == 0 {
			return errors.New("connectors.kafka: brokers is required")
		}
		for _, b := range k.Brokers {
			if _, _, err := net.SplitHostPort(b); err != nil {
				return fmt.Errorf("connectors.kafka: broker %q: %w", b, err)
			}
		}
		if k.Topic == "" {
			return errors.New("connectors.kafka: topic is required")
		}
		if err := k.Delivery.validate(); err != nil {
			return fmt.Errorf("connectors.kafka: %w", err)
		}
	}
	return nil
}

func (s *SyslogConfig) validate() error {
	if _, _, err := net.SplitHostPort(s.Address); err != nil {
		return fmt.Errorf("address %q: %w", s.Address, err)
	}
	switch strings.ToLower(s.Protocol) {
	case "", "tcp":
		switch s.Framing {
		case "", framingOctetCounting, framingLF:
		default:
			return fmt.Errorf("framing %q: must be %s or %s", s.Framing, framingOctetCounting, framingLF)
		}
	case "udp":
		if s.Framing != "" {
			return errors.New("framing applies to tcp only; udp sends one message per datagram")
		}
	default:
		return fmt.Errorf("protocol %q: must be tcp or udp", s.Protocol)
	}
	if s.Facility != "" {
		if _, ok := syslogFacilities[strings.ToLower(s.Facility)]; !ok {
			return fmt.Errorf("unknown facility %q", s.Facility)
		}
	}
	return s.Delivery.validate()
}

var esTimeUnit = regexp.MustCompile(`^[0-9]+(d|h|m|s|ms)$`)

func (e *ElasticConfig) validate() error {
	if err := checkURL(e.URL); err != nil {
		return err
	}
	if (e.Username == "") != (e.Password == "") {
		return errors.New("username and password go together")
	}
	if e.APIKey != "" && e.Username != "" {
		return errors.New("set api_key or username and password, not both")
	}
	if e.IndexPrefix != "" && (e.IndexPrefix != strings.ToLower(e.IndexPrefix) || strings.ContainsAny(e.IndexPrefix, ` "*\<|,>/?#:`)) {
		return fmt.Errorf("index_prefix %q is not a valid index name", e.IndexPrefix)
	}
	if d := e.ILM.DeleteAfter; d != "" && !esTimeUnit.MatchString(d) {
		return fmt.Errorf("ilm.delete_after %q: use an Elasticsearch time unit such as 90d", d)
	}
	return e.Delivery.validate()
}

// checkURL requires an absolute http or https URL.
func checkURL(raw string) error {
	if raw == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("url %q: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url %q: must be an absolute http or https URL", raw)
	}
	return nil
}
