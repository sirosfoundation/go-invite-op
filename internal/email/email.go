package email

import (
"fmt"
"net/smtp"

"go.uber.org/zap"

"github.com/sirosfoundation/go-invite-op/internal/config"
)

// Sender is the interface for sending email.
type Sender interface {
SendCode(to, code string) error
}

// SMTPSender sends invite codes via SMTP.
type SMTPSender struct {
cfg    config.SMTPConfig
logger *zap.Logger
}

// NewSMTPSender creates a new SMTP email sender.
func NewSMTPSender(cfg config.SMTPConfig, logger *zap.Logger) *SMTPSender {
return &SMTPSender{cfg: cfg, logger: logger.Named("email")}
}

// SendCode sends an invite code to the given email address.
func (s *SMTPSender) SendCode(to, code string) error {
from := s.cfg.From
subject := "Your invite code"
body := fmt.Sprintf("Your invite code is: %s", code)
msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", from, to, subject, body)

addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
var auth smtp.Auth
if s.cfg.Username != "" {
auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
}

if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg)); err != nil {
s.logger.Error("Failed to send email", zap.String("to", to), zap.Error(err))
return fmt.Errorf("sending email: %w", err)
}

s.logger.Info("Sent invite code", zap.String("to", to))
return nil
}

// LogSender logs the code instead of emailing (for development).
type LogSender struct {
logger *zap.Logger
}

// NewLogSender creates a new log-only email sender.
func NewLogSender(logger *zap.Logger) *LogSender {
return &LogSender{logger: logger.Named("email")}
}

// SendCode logs the invite code.
func (s *LogSender) SendCode(to, code string) error {
s.logger.Info("Invite code (dev mode)", zap.String("to", to), zap.String("code", code))
return nil
}
