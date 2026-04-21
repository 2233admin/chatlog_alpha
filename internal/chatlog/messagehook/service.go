package messagehook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sjzar/chatlog/internal/chatlog/conf"
	"github.com/sjzar/chatlog/internal/model"
	"github.com/sjzar/chatlog/internal/wechatdb"
)

const (
	defaultPollInterval = 2 * time.Second
	maxTalkerScan       = 300
	maxMsgScanPerTalker = 200
	maxContextScan      = 2000
)

type Config interface {
	GetMessageHook() *conf.MessageHook
}

type ContextMessage struct {
	Seq      int64  `json:"seq"`
	Time     string `json:"time"`
	Sender   string `json:"sender"`
	IsSelf   bool   `json:"is_self"`
	Type     int64  `json:"type"`
	Content  string `json:"content"`
	Position string `json:"position"`
}

type Event struct {
	ID             int64            `json:"id"`
	CreatedAt      string           `json:"created_at"`
	Keyword        string           `json:"keyword"`
	Talker         string           `json:"talker"`
	TalkerName     string           `json:"talker_name"`
	Sender         string           `json:"sender"`
	SenderName     string           `json:"sender_name"`
	TriggerSeq     int64            `json:"trigger_seq"`
	TriggerTime    string           `json:"trigger_time"`
	TriggerContent string           `json:"trigger_content"`
	Context        []ContextMessage `json:"context"`
}

type Service struct {
	conf       Config
	db         *wechatdb.DB
	httpClient *http.Client
	notify     func(Event)
	seenSeq    map[string]int64
	startAt    time.Time
}

func New(conf Config, db *wechatdb.DB, notify func(Event)) *Service {
	return &Service{
		conf:       conf,
		db:         db,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		notify:     notify,
		seenSeq:    make(map[string]int64),
		startAt:    time.Now(),
	}
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.scanOnce(); err != nil {
				log.Debug().Err(err).Msg("message hook scan failed")
			}
		}
	}
}

func (s *Service) scanOnce() error {
	cfg := s.conf.GetMessageHook()
	if cfg == nil {
		return nil
	}
	keywords := parseKeywords(cfg.Keywords)
	if len(keywords) == 0 {
		return nil
	}
	sessions, err := s.db.GetSessions("", maxTalkerScan, 0)
	if err != nil || sessions == nil {
		return err
	}
	now := time.Now()
	for _, sess := range sessions.Items {
		if sess == nil || strings.TrimSpace(sess.UserName) == "" {
			continue
		}
		_ = s.scanTalker(now, sess.UserName, keywords, cfg)
	}
	return nil
}

func (s *Service) scanTalker(now time.Time, talker string, keywords []string, cfg *conf.MessageHook) error {
	start := s.startAt.Add(-15 * time.Second)
	if lastSeq := s.lastSeenSeq(talker); lastSeq > 0 {
		start = now.Add(-10 * time.Minute)
		_ = lastSeq
	}

	msgs, err := s.db.GetMessages(start, now.Add(time.Minute), talker, "", "", maxMsgScanPerTalker, 0)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m == nil {
			continue
		}
		if s.isSeen(talker, m.Seq) {
			continue
		}
		s.markSeen(talker, m.Seq)
		if m.Time.Before(s.startAt) || m.IsSelf {
			continue
		}

		content := strings.TrimSpace(m.PlainTextContent())
		if content == "" {
			content = strings.TrimSpace(m.Content)
		}
		if content == "" {
			continue
		}
		kw := matchKeyword(content, keywords)
		if kw == "" {
			continue
		}
		evt := s.buildEvent(m, kw, content, cfg)
		s.dispatch(cfg, evt)
	}
	return nil
}

func (s *Service) buildEvent(trigger *model.Message, keyword, triggerContent string, cfg *conf.MessageHook) Event {
	talker := trigger.Talker
	if strings.TrimSpace(talker) == "" {
		talker = trigger.TalkerName
	}
	talkerName := trigger.TalkerName
	if talkerName == "" {
		talkerName = talker
	}
	sender := trigger.Sender
	if sender == "" {
		sender = trigger.SenderName
	}
	senderName := trigger.SenderName
	if senderName == "" {
		senderName = sender
	}
	beforeCount := 5
	afterCount := 5
	if cfg != nil && cfg.BeforeCount > 0 {
		beforeCount = cfg.BeforeCount
	}
	if cfg != nil && cfg.AfterCount > 0 {
		afterCount = cfg.AfterCount
	}
	evt := Event{
		ID:             time.Now().UnixNano(),
		CreatedAt:      time.Now().Format(time.RFC3339),
		Keyword:        keyword,
		Talker:         talker,
		TalkerName:     talkerName,
		Sender:         sender,
		SenderName:     senderName,
		TriggerSeq:     trigger.Seq,
		TriggerTime:    trigger.Time.Format("2006-01-02 15:04:05"),
		TriggerContent: triggerContent,
	}
	evt.Context = s.loadContext(trigger, beforeCount, afterCount)
	return evt
}

func (s *Service) loadContext(trigger *model.Message, beforeCount, afterCount int) []ContextMessage {
	msgs, err := s.db.GetMessages(trigger.Time.Add(-24*time.Hour), trigger.Time.Add(24*time.Hour), trigger.Talker, "", "", maxContextScan, 0)
	if err != nil || len(msgs) == 0 {
		return nil
	}
	idx := -1
	for i, m := range msgs {
		if m != nil && m.Seq == trigger.Seq {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	start := idx - beforeCount
	if start < 0 {
		start = 0
	}
	end := idx + afterCount + 1
	if end > len(msgs) {
		end = len(msgs)
	}

	out := make([]ContextMessage, 0, end-start)
	for i := start; i < end; i++ {
		m := msgs[i]
		if m == nil {
			continue
		}
		content := strings.TrimSpace(m.PlainTextContent())
		if content == "" {
			content = strings.TrimSpace(m.Content)
		}
		position := "before"
		if i == idx {
			position = "trigger"
		} else if i > idx {
			position = "after"
		}
		sender := m.SenderName
		if sender == "" {
			sender = m.Sender
		}
		out = append(out, ContextMessage{
			Seq:      m.Seq,
			Time:     m.Time.Format("2006-01-02 15:04:05"),
			Sender:   sender,
			IsSelf:   m.IsSelf,
			Type:     m.Type,
			Content:  content,
			Position: position,
		})
	}
	return out
}

func (s *Service) dispatch(cfg *conf.MessageHook, evt Event) {
	mode := strings.ToLower(strings.TrimSpace(cfg.NotifyMode))
	if mode == "" {
		mode = conf.HookNotifyMCP
	}
	if (mode == conf.HookNotifyMCP || mode == conf.HookNotifyBoth) && s.notify != nil {
		s.notify(evt)
	}
	if mode == conf.HookNotifyPost || mode == conf.HookNotifyBoth {
		url := strings.TrimSpace(cfg.PostURL)
		if url == "" {
			return
		}
		body, err := json.Marshal(evt)
		if err != nil {
			return
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			log.Debug().Err(err).Str("url", url).Msg("message hook post failed")
			return
		}
		defer resp.Body.Close()
	}
}

func (s *Service) lastSeenSeq(talker string) int64 {
	return s.seenSeq[talker]
}

func (s *Service) isSeen(talker string, seq int64) bool {
	return seq <= s.seenSeq[talker]
}

func (s *Service) markSeen(talker string, seq int64) {
	if seq > s.seenSeq[talker] {
		s.seenSeq[talker] = seq
	}
}

func parseKeywords(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "|", "｜")
	parts := strings.Split(raw, "｜")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		k := strings.TrimSpace(p)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func matchKeyword(content string, keywords []string) string {
	for _, k := range keywords {
		if strings.Contains(content, k) {
			return k
		}
	}
	return ""
}
