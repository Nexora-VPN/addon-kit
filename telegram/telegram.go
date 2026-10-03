// Package telegram is a small Telegram Bot API client for addons: send a
// message, a photo or a document, edit it, answer a button, read a member's
// status and a file, and read updates by long polling. A server in Iran
// reaches Telegram through a SOCKS5 or HTTP proxy (HTTPClient) or a Bot API
// mirror (Bot.APIBase); the same client speaks to Bale, whose Bot API is
// Telegram's at another address (BaleAPI).
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ValidProxy checks a proxy URL: socks5, socks5h, http or https, with a host.
func ValidProxy(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return errors.New("not a proxy URL (socks5://host:port or http://host:port)")
	}
	switch u.Scheme {
	case "socks5", "socks5h", "http", "https":
		return nil
	}
	return errors.New("proxy scheme must be socks5, socks5h, http or https")
}

// HTTPClient is a client through the proxy, or straight when it is empty —
// never the environment's proxy: the operator chose one or none.
func HTTPClient(proxy string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if proxy != "" {
		if err := ValidProxy(proxy); err != nil {
			return nil, err
		}
		u, _ := url.Parse(proxy)
		if u.Scheme == "socks5h" {
			// Go's SOCKS5 dialer always hands the proxy the host name, which
			// is what socks5h means elsewhere; accept the spelling people copy.
			u.Scheme = "socks5"
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: transport, Timeout: 90 * time.Second}, nil
}

// The Bot API addresses an addon is likely to need. An empty APIBase is
// Telegram's.
const (
	TelegramAPI = "https://api.telegram.org"
	BaleAPI     = "https://tapi.bale.ai"
)

// Bot is one bot token at one API address.
type Bot struct {
	Token   string
	APIBase string
	HTTP    *http.Client
}

// Error is the Bot API refusing a call.
type Error struct {
	Code        int
	Description string
	// RetryAfter is the flood-control wait Telegram asked for, in seconds.
	RetryAfter int
}

func (e *Error) Error() string { return fmt.Sprintf("telegram: %d %s", e.Code, e.Description) }

type answer struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func (b Bot) base() string {
	base := strings.TrimRight(b.APIBase, "/")
	if base == "" {
		base = TelegramAPI
	}
	return base
}

func (b Bot) url(method string) string { return b.base() + "/bot" + b.Token + "/" + method }

// ID is the bot's numeric id, the part of the token before the colon.
// Update ids are counted per bot, so a poll's offset belongs to one.
func (b Bot) ID() string {
	id, _, _ := strings.Cut(b.Token, ":")
	return id
}

func (b Bot) do(req *http.Request, out any) error {
	client := b.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// The URL holds the token: never let it into an error message.
		return fmt.Errorf("telegram: %s", strings.ReplaceAll(err.Error(), b.Token, "<token>"))
	}
	defer resp.Body.Close()
	var a answer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&a); err != nil {
		return fmt.Errorf("telegram: HTTP %d", resp.StatusCode)
	}
	if !a.OK {
		return &Error{Code: a.ErrorCode, Description: a.Description, RetryAfter: a.Parameters.RetryAfter}
	}
	if out != nil {
		return json.Unmarshal(a.Result, out)
	}
	return nil
}

// Call is one method with JSON parameters.
func (b Bot) Call(ctx context.Context, method string, params, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url(method), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return b.do(req, out)
}

// Upload is one method with a file: the other parameters as form fields.
func (b Bot) Upload(ctx context.Context, method string, fields map[string]string, field, name string, data []byte, out any) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	part, err := w.CreateFormFile(field, name)
	if err != nil {
		return err
	}
	_, _ = part.Write(data)
	if err := w.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url(method), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	return b.do(req, out)
}

// Updates long-polls for updates after offset.
func (b Bot) Updates(ctx context.Context, offset int64, wait time.Duration) ([]Update, error) {
	var out []Update
	ctx, cancel := context.WithTimeout(ctx, wait+15*time.Second)
	defer cancel()
	err := b.Call(ctx, "getUpdates", map[string]any{
		"offset": offset, "timeout": int(wait.Seconds()), "allowed_updates": []string{"message", "callback_query"},
	}, &out)
	return out, err
}

// Send is a text message with optional buttons.
func (b Bot) Send(ctx context.Context, chatID int64, html string, kb *Keyboard) (Message, error) {
	params := map[string]any{"chat_id": chatID, "text": html, "parse_mode": "HTML", "link_preview_options": map[string]bool{"is_disabled": true}}
	if kb != nil {
		params["reply_markup"] = kb
	}
	var m Message
	err := b.Call(ctx, "sendMessage", params, &m)
	return m, err
}

// Edit replaces a message's text and buttons.
func (b Bot) Edit(ctx context.Context, chatID, messageID int64, html string, kb *Keyboard) error {
	params := map[string]any{
		"chat_id": chatID, "message_id": messageID, "text": html, "parse_mode": "HTML",
		"link_preview_options": map[string]bool{"is_disabled": true},
	}
	if kb != nil {
		params["reply_markup"] = kb
	}
	return b.Call(ctx, "editMessageText", params, nil)
}

// SendPhoto is a picture with a caption; name is the file's name.
func (b Bot) SendPhoto(ctx context.Context, chatID int64, name string, image []byte, caption string, kb *Keyboard) error {
	fields := map[string]string{"chat_id": fmt.Sprint(chatID), "caption": caption, "parse_mode": "HTML"}
	if kb != nil {
		fields["reply_markup"] = kb.JSON()
	}
	return b.Upload(ctx, "sendPhoto", fields, "photo", name, image, nil)
}

// Blocked reports whether err is the Bot API saying the user has blocked
// the bot, deleted their account or never started it — a chat this bot can
// no longer write to, as against a failure worth retrying.
func Blocked(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	if e.Code == 403 {
		return true
	}
	d := strings.ToLower(e.Description)
	return e.Code == 400 && (strings.Contains(d, "chat not found") || strings.Contains(d, "user not found"))
}

// Answer answers a button press; text, when given, shows as a toast.
func (b Bot) Answer(ctx context.Context, callbackID, text string) {
	_ = b.Call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": callbackID, "text": text}, nil)
}

// MemberStatus is a user's standing in a chat: creator, administrator,
// member, restricted, left or kicked.
func (b Bot) MemberStatus(ctx context.Context, chat string, userID int64) (string, error) {
	var m struct {
		Status string `json:"status"`
	}
	err := b.Call(ctx, "getChatMember", map[string]any{"chat_id": chat, "user_id": userID}, &m)
	return m.Status, err
}

// SetMenuButton makes the button beside every chat's text field open the
// mini-app at url.
func (b Bot) SetMenuButton(ctx context.Context, text, url string) error {
	return b.Call(ctx, "setChatMenuButton", map[string]any{
		"menu_button": map[string]any{"type": "web_app", "text": text, "web_app": WebApp{URL: url}},
	}, nil)
}

// Me is the bot itself.
func (b Bot) Me(ctx context.Context) (User, error) {
	var u User
	err := b.Call(ctx, "getMe", map[string]any{}, &u)
	return u, err
}

// File downloads a file someone sent, up to max bytes.
func (b Bot) File(ctx context.Context, fileID string, max int64) ([]byte, error) {
	var f struct {
		Path string `json:"file_path"`
		Size int64  `json:"file_size"`
	}
	if err := b.Call(ctx, "getFile", map[string]any{"file_id": fileID}, &f); err != nil {
		return nil, err
	}
	if f.Size > max {
		return nil, fmt.Errorf("the file is larger than %d bytes", max)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.base()+"/file/bot"+b.Token+"/"+f.Path, nil)
	if err != nil {
		return nil, err
	}
	client := b.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("telegram: %s", strings.ReplaceAll(err.Error(), b.Token, "<token>"))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram: the file answered %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if int64(len(data)) > max {
		return nil, fmt.Errorf("the file is larger than %d bytes", max)
	}
	return data, err
}

// Update is one update.
type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message,omitempty"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
}

// Message is a message.
type Message struct {
	MessageID int64       `json:"message_id"`
	Chat      Chat        `json:"chat"`
	From      *User       `json:"from,omitempty"`
	Text      string      `json:"text,omitempty"`
	Caption   string      `json:"caption,omitempty"`
	ThreadID  int64       `json:"message_thread_id,omitempty"`
	IsTopic   bool        `json:"is_topic_message,omitempty"`
	Photo     []PhotoSize `json:"photo,omitempty"`
	Document  *Document   `json:"document,omitempty"`
	Contact   *Contact    `json:"contact,omitempty"`
}

// PhotoSize is one size of a photo; the last is the largest.
type PhotoSize struct {
	FileID string `json:"file_id"`
	// FileUniqueID is the same for the same file whoever sends it, and
	// however often it is forwarded.
	FileUniqueID string `json:"file_unique_id"`
	FileSize     int64  `json:"file_size"`
}

// Document is a file sent as a file.
type Document struct {
	FileID       string `json:"file_id"`
	FileUniqueID string `json:"file_unique_id"`
	FileName     string `json:"file_name"`
	MimeType     string `json:"mime_type"`
	FileSize     int64  `json:"file_size"`
}

// Contact is a shared phone number.
type Contact struct {
	PhoneNumber string `json:"phone_number"`
	UserID      int64  `json:"user_id"`
}

// Chat is a chat.
type Chat struct {
	ID    int64  `json:"id"`
	Type  string `json:"type,omitempty"`
	Title string `json:"title,omitempty"`
}

// User is a Telegram user.
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username,omitempty"`
	FirstName    string `json:"first_name,omitempty"`
	LastName     string `json:"last_name,omitempty"`
	LanguageCode string `json:"language_code,omitempty"`
}

// CallbackQuery is a button pressed.
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message,omitempty"`
	Data    string   `json:"data"`
}

// Button is an inline button: a callback, a link, or a mini-app.
type Button struct {
	Text   string  `json:"text"`
	Data   string  `json:"callback_data,omitempty"`
	URL    string  `json:"url,omitempty"`
	WebApp *WebApp `json:"web_app,omitempty"`
}

// WebApp is a mini-app a button opens.
type WebApp struct {
	URL string `json:"url"`
}

// Keyboard is inline buttons, row by row; an empty one removes them.
type Keyboard struct {
	Rows [][]Button `json:"inline_keyboard"`
}

// MarshalJSON writes no buttons as an empty array: the Bot API refuses
// null, and an edit carrying it fails whole.
func (k Keyboard) MarshalJSON() ([]byte, error) {
	rows := k.Rows
	if rows == nil {
		rows = [][]Button{}
	}
	return json.Marshal(struct {
		Rows [][]Button `json:"inline_keyboard"`
	}{rows})
}

// JSON is the keyboard as a form field.
func (k Keyboard) JSON() string {
	b, _ := json.Marshal(k)
	return string(b)
}
