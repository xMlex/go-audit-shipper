package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elastic/go-libaudit/auparse"
	"github.com/nxadm/tail"
	"github.com/spf13/cobra"
	"github.com/xMlex/go-audit-shipper/internal/model"
)

var (
	auditdLogFile   = "/var/log/audit/audit.log"
	auditdStateFile = "offset.state"
	output          = ""
)

var rootCmd = &cobra.Command{
	Short: "Run Go Auditd Shipper",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Printf("Starting Go Auditd Shipper %s (built: %s, commit: %s)", model.Version, model.BuildDate, model.ShortCommit)

		offset := loadOffset(auditdStateFile)
		config := tail.Config{
			Follow: true,
			ReOpen: true,
			Logger: tail.DiscardingLogger,
		}
		if offset > 0 {
			config.Location = &tail.SeekInfo{Offset: offset, Whence: 0}
		}
		tailFile, err := tail.TailFile(auditdLogFile, config)
		if err != nil {
			log.Fatal(err)
		}

		var sender model.Sender
		proto, addr, _ := strings.Cut(output, "://")
		switch proto {
		case "gelf_udp":
			sender, err = model.NewGelfSender(addr)
			if err != nil {
				log.Fatal(err)
			}
		case "gelf_tcp":
			return errors.New("TCP output not supported yet.")
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
					saveOffset(auditdStateFile, pos)
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
		return err
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&auditdLogFile, "log", auditdLogFile, "audit log file (default is "+auditdLogFile+"")
	rootCmd.PersistentFlags().StringVar(&auditdStateFile, "state", auditdStateFile, "state file (default is "+auditdStateFile+"")
	rootCmd.PersistentFlags().StringVar(&output, "output", auditdStateFile, "example: gelf_udp://host:port, gelf_tcp://, syslog_udp://")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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
