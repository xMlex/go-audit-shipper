package model

import "github.com/elastic/go-libaudit/auparse"

type Field struct {
	Value    string
	IsQuoted bool
}

type Sender interface {
	Send(events []*auparse.AuditMessage) error
}
