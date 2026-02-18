package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	_ "path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elastic/go-libaudit/auparse"
	"github.com/nxadm/tail"
	"github.com/xMlex/go-audit-shipper/internal/model"
)

func loadOffset(stateFile string) int64 {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return 0 // включая отсутствие файла — поведение по умолчанию
	}
	offset, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return offset
}

func saveOffset(stateFile string, offset int64) error {
	return os.WriteFile(stateFile, []byte(fmt.Sprintf("%d", offset)), 0644)
}

func main() {
	logFile := flag.String("log", "/var/log/audit/audit.log", "audit log file")
	stateFile := flag.String("state", "offset.state", "state file")
	//output := flag.String("output", "gelf_udp://localhost:12201", "output: gelf_udp://host:port, gelf_tcp://, syslog_udp://")
	output := flag.String("output", "", "output: gelf_udp://host:port, gelf_tcp://, syslog_udp://")
	flag.Parse()

	offset := loadOffset(*stateFile)
	config := tail.Config{
		Follow: true,
		ReOpen: true,
		Logger: tail.DiscardingLogger,
	}
	if offset > 0 {
		config.Location = &tail.SeekInfo{Offset: offset, Whence: 0}
	}
	tailFile, err := tail.TailFile(*logFile, config)
	if err != nil {
		log.Fatal(err)
	}

	var sender model.Sender
	proto, addr, _ := strings.Cut(*output, "://")
	switch proto {
	case "gelf_udp":
		sender, err = model.NewGelfSender(addr)
		if err != nil {
			log.Fatal(err)
		}
	case "gelf_tcp": //TODO
		log.Fatal("TCP output not supported yet.")
	default:
		sender = model.StdoutSender{}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	lastSequence := uint32(0)
	var currentRecords []*auparse.AuditMessage
	mt := sync.Mutex{}
	lastActivity := time.Now()

	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	flush := func() {
		if len(currentRecords) == 0 || lastSequence == 0 {
			return
		}

		log.Printf("Sent batch of %d messages", len(currentRecords))
		if err := sender.Send(currentRecords); err != nil {
			log.Println("send error", err)
			return
		}

		currentRecords = currentRecords[:0] // Очищаем срез
		lastSequence = 0
		lastActivity = time.Now()
	}

	go func() {
		for {
			select {
			case <-sigChan:
				tailFile.Stop()
				return
			case <-ticker.C:
				// send loaded
				mt.Lock()
				if time.Since(lastActivity) > time.Second*5 {
					flush()
				}
				mt.Unlock()
				// save pos
				pos, _ := tailFile.Tell()
				saveOffset(*stateFile, pos)
				break
			}
		}
	}()

	for line := range tailFile.Lines {
		if line.Err != nil {
			log.Println("[ERROR]Lines read", line.Err.Error())
			break
		}
		msg, err := auparse.ParseLogLine(line.Text)
		if err != nil {
			log.Println("[ERROR]ParseLogLine", err.Error(), "line:", line.Text)
			continue
		}

		mt.Lock()
		if lastSequence != msg.Sequence {
			flush()
			lastSequence = msg.Sequence
		}
		currentRecords = append(currentRecords, msg)
		lastActivity = time.Now()
		mt.Unlock()
	}

	mt.Lock()
	flush()
	mt.Unlock()
}
