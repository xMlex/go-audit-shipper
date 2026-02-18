package model

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/Graylog2/go-gelf/gelf"
	"github.com/elastic/go-libaudit/auparse"
)

type StdoutSender struct {
}

func (s StdoutSender) Send(events []*auparse.AuditMessage) error {
	data, err := json.Marshal(events)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write([]byte("\n"))
	return err
}

type GelfSender struct {
	hostname string
	writer   *gelf.Writer
}

func NewGelfSender(addr string) (*GelfSender, error) {
	writer, err := gelf.NewWriter(addr)
	if err != nil {
		return nil, err
	}
	w := &GelfSender{writer: writer}
	if w.hostname, err = os.Hostname(); err != nil {
		return nil, err
	}
	writer.CompressionType = gelf.CompressGzip
	writer.Facility = "go-audit"
	return w, nil
}

func (s *GelfSender) Send(events []*auparse.AuditMessage) error {
	if events == nil || len(events) < 1 {
		return nil
	}

	msg := &gelf.Message{
		Version:  "1.1",
		Facility: s.writer.Facility,
		Host:     s.hostname,
		Level:    6,
		TimeUnix: float64(events[0].Timestamp.Unix()),
		Short:    "Audit event " + strconv.FormatUint(uint64(events[0].Sequence), 10) + " - " + events[0].RecordType.String(),
		Extra:    make(map[string]interface{}),
	}

	doublesOfType := make(map[string]int)
	for _, event := range events {
		eventType := event.RecordType.String()
		index, found := doublesOfType[eventType]
		if found {
			doublesOfType[event.RecordType.String()]++
			eventType = eventType + "_" + strconv.Itoa(index)
		} else {
			doublesOfType[event.RecordType.String()] = 1 // 0 its previous
		}
		data, err := event.Data()
		if err != nil {
			msg.Extra[eventType] = event.RawData
			continue
		}
		for typeName, typeVal := range data {
			msg.Extra[eventType+"_"+typeName] = typeVal
		}
	}

	return s.writer.WriteMessage(msg)
}
