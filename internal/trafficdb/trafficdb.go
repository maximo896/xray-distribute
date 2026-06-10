package trafficdb

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xray-distribute/internal/model"
)

const maxRetentionDays = 7

type DB struct {
	db      *sql.DB
	dbDir   string // db文件所在目录
	dbPath  string // 当前db文件路径
	current string // 当前日期字符串，用于判断是否需要滚动
	mu      sync.RWMutex
}

type Match struct {
	Source    string `json:"source"`
	ID        int64  `json:"id"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Raw       string `json:"raw"`
	CreatedAt string `json:"created_at"`
}

// Open 打开或创建当天的traffic db
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	dbDir := filepath.Dir(path)
	today := time.Now().Format("2006-01-02")
	dbPath := datedDBPath(dbDir, today)

	db, err := openSQLite(dbPath)
	if err != nil {
		return nil, err
	}
	t := &DB{db: db, dbDir: dbDir, dbPath: dbPath, current: today}
	if err := t.init(); err != nil {
		db.Close()
		return nil, err
	}

	// 启动时清理过期db
	t.cleanOldDBs()

	return t, nil
}

// datedDBPath 返回按日期命名的db路径，如 traffic-2026-06-07.db
func datedDBPath(dbDir, date string) string {
	return filepath.Join(dbDir, "traffic-"+date+".db")
}

func openSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	for _, pragma := range []string{
		`pragma journal_mode=WAL`,
		`pragma synchronous=NORMAL`,
		`pragma busy_timeout=10000`,
		`pragma temp_store=MEMORY`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

// Close 关闭数据库
func (t *DB) Close() error {
	if t == nil || t.db == nil {
		return nil
	}
	return t.db.Close()
}

// Rotate 检查是否需要滚动到新一天的db，如果需要则切换
func (t *DB) Rotate() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if today == t.current {
		return nil // 同一天，无需滚动
	}

	newPath := datedDBPath(t.dbDir, today)
	newDB, err := openSQLite(newPath)
	if err != nil {
		return fmt.Errorf("open new traffic db %s: %w", newPath, err)
	}

	nt := &DB{db: newDB, dbDir: t.dbDir, dbPath: newPath, current: today}
	if err := nt.init(); err != nil {
		newDB.Close()
		return fmt.Errorf("init new traffic db: %w", err)
	}

	// 关闭旧db
	oldDB := t.db
	t.db = newDB
	t.dbPath = newPath
	t.current = today

	if oldDB != nil {
		oldDB.Close()
	}

	// 清理过期db
	t.cleanOldDBs()

	return nil
}

// cleanOldDBs 删除超过maxRetentionDays天的db文件
func (t *DB) cleanOldDBs() {
	entries, err := filepath.Glob(filepath.Join(t.dbDir, "traffic-????.??-??*.db"))
	if err != nil {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -maxRetentionDays)
	for _, entry := range entries {
		// 从文件名中提取日期: traffic-2026-06-07.db -> 2026-06-07
		base := filepath.Base(entry)
		dateStr := strings.TrimPrefix(base, "traffic-")
		dateStr = strings.TrimSuffix(dateStr, ".db")
		if len(dateStr) < 10 {
			continue
		}
		fileDate, err := time.Parse("2006-01-02", dateStr[:10])
		if err != nil {
			continue
		}
		if fileDate.Before(cutoff) {
			os.Remove(entry)
		}
	}
}

func (t *DB) init() error {
	stmts := []string{
		`create table if not exists mirror_traffic (
			id integer primary key autoincrement,
			agent_id text, method text, url text, headers text, body blob,
			protocol text, timestamp integer, raw text, created_at text
		)`,
		`create table if not exists xray_requests (
			id integer primary key autoincrement,
			method text, url text, headers text, body blob, raw text,
			response_status integer, response text, created_at text
		)`,
		`create table if not exists oob_interactions (
			id integer primary key autoincrement,
			protocol text, full_id text, raw_request text, raw_response text,
			remote_address text, timestamp integer, matched_source string,
			matched_id integer, created_at text
		)`,
		`create table if not exists request_tokens (
			id integer primary key autoincrement,
			token text not null,
			source text not null,
			request_id integer not null,
			created_at text
		)`,
		`create index if not exists idx_mirror_created_at on mirror_traffic(created_at)`,
		`create index if not exists idx_xray_created_at on xray_requests(created_at)`,
		`create index if not exists idx_oob_full_id on oob_interactions(full_id)`,
		`create index if not exists idx_request_tokens_token on request_tokens(token)`,
		`create index if not exists idx_request_tokens_source_id on request_tokens(source, request_id)`,
	}
	for _, stmt := range stmts {
		if _, err := t.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (t *DB) RecordMirror(req *model.MirrorRequest) (int64, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	headers, _ := json.Marshal(req.Headers)
	raw := rawMirror(req)
	res, err := execWithRetry(t.db, `insert into mirror_traffic(agent_id,method,url,headers,body,protocol,timestamp,raw,created_at)
		values(?,?,?,?,?,?,?,?,?)`,
		req.AgentID, req.Method, req.URL, string(headers), req.Body, req.Protocol, req.Timestamp, raw, time.Now().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := recordRequestTokens(t.db, "mirror", id, req.URL, raw, string(req.Body)); err != nil {
		return 0, err
	}
	return id, nil
}

func (t *DB) RecordXRayRequest(method, url string, headers map[string][]string, body []byte, status int, response string) (int64, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	headersJSON, _ := json.Marshal(headers)
	raw := rawHTTP(method, url, headers, body)
	res, err := execWithRetry(t.db, `insert into xray_requests(method,url,headers,body,raw,response_status,response,created_at)
		values(?,?,?,?,?,?,?,?)`,
		method, url, string(headersJSON), body, raw, status, response, time.Now().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := recordRequestTokens(t.db, "xray", id, url, raw, string(body)); err != nil {
		return 0, err
	}
	return id, nil
}

func (t *DB) RecordOOB(interaction model.OOBInteraction) (*Match, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// 先在当前db中查找匹配
	needles := interactionNeedles(interaction)
	tokens := candidateIDs(interaction.FullID)

	match, _ := findMatchByTokensInDB(t.db, tokens)
	if match == nil {
		match, _ = t.findMatchAcrossDBsByTokens(tokens)
	}
	if match == nil {
		match, _ = t.findMatchByNeedles(needles)
	}

	// 如果当前db没找到，跨所有db查找
	if match == nil {
		match, _ = t.findMatchAcrossDBs(needles)
	}

	var source string
	var id any
	if match != nil {
		source = match.Source
		id = match.ID
	}
	_, err := execWithRetry(t.db, `insert into oob_interactions(protocol,full_id,raw_request,raw_response,remote_address,timestamp,matched_source,matched_id,created_at)
		values(?,?,?,?,?,?,?,?,?)`,
		interaction.Protocol, interaction.FullID, interaction.RawRequest, interaction.RawResponse,
		interaction.RemoteAddress, interaction.Timestamp.Unix(), source, id, time.Now().Format(time.RFC3339Nano))
	return match, err
}

func (t *DB) FindMatch(fullID string) (*Match, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	tokens := candidateIDs(fullID)
	if m, err := findMatchByTokensInDB(t.db, tokens); err != nil {
		return nil, err
	} else if m != nil {
		return m, nil
	}
	if m, err := t.findMatchAcrossDBsByTokens(tokens); err != nil {
		return nil, err
	} else if m != nil {
		return m, nil
	}

	// 先在当前db查找
	if m, err := t.findMatchByNeedles(tokens); err != nil {
		return nil, err
	} else if m != nil {
		return m, nil
	}
	// 跨所有db查找
	return t.findMatchAcrossDBs(tokens)
}

// findMatchAcrossDBs 跨所有db文件查找匹配
func (t *DB) findMatchAcrossDBs(needles []string) (*Match, error) {
	entries, err := filepath.Glob(filepath.Join(t.dbDir, "traffic-????.??-??*.db"))
	if err != nil {
		return nil, err
	}

	// 按日期倒序排列，最新的先查
	sort.Sort(sort.Reverse(sort.StringSlice(entries)))

	for _, entry := range entries {
		if entry == t.dbPath {
			continue // 当前db已经查过了
		}
		db, err := openSQLite(entry)
		if err != nil {
			continue
		}
		m, err := findMatchInDB(db, needles)
		db.Close()
		if err != nil {
			continue
		}
		if m != nil {
			return m, nil
		}
	}
	return nil, nil
}

func (t *DB) findMatchAcrossDBsByTokens(tokens []string) (*Match, error) {
	entries, err := filepath.Glob(filepath.Join(t.dbDir, "traffic-????.??-??*.db"))
	if err != nil {
		return nil, err
	}

	sort.Sort(sort.Reverse(sort.StringSlice(entries)))

	for _, entry := range entries {
		if entry == t.dbPath {
			continue
		}
		db, err := openSQLite(entry)
		if err != nil {
			continue
		}
		m, err := findMatchByTokensInDB(db, tokens)
		db.Close()
		if err != nil {
			continue
		}
		if m != nil {
			return m, nil
		}
	}
	return nil, nil
}

// findMatchInDB 在指定的db连接中查找匹配
func findMatchInDB(db *sql.DB, needles []string) (*Match, error) {
	needles = uniqueStrings(needles)
	for _, needle := range needles {
		if m, err := findInDB(db, "xray_requests", needle); err != nil {
			return nil, err
		} else if m != nil {
			return m, nil
		}
	}
	for _, needle := range needles {
		if m, err := findInDB(db, "mirror_traffic", needle); err != nil {
			return nil, err
		} else if m != nil {
			return m, nil
		}
	}
	return nil, nil
}

func findInDB(db *sql.DB, table, needle string) (*Match, error) {
	if needle == "" {
		return nil, nil
	}
	source := "mirror"
	if table == "xray_requests" {
		source = "xray"
	}
	row := db.QueryRow(fmt.Sprintf(`select id, method, url, raw, created_at from %s
		where url like ? or raw like ? order by id desc limit 1`, table), "%"+needle+"%", "%"+needle+"%")
	var m Match
	m.Source = source
	err := row.Scan(&m.ID, &m.Method, &m.URL, &m.Raw, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func findMatchByTokensInDB(db *sql.DB, tokens []string) (*Match, error) {
	tokens = uniqueStrings(tokens)
	for _, token := range tokens {
		row := db.QueryRow(`select source, request_id from request_tokens
			where token = ? order by id desc limit 1`, strings.ToLower(token))
		var source string
		var requestID int64
		err := row.Scan(&source, &requestID)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no such table") {
				return nil, nil
			}
			return nil, err
		}
		m, err := findByIDInDB(db, source, requestID)
		if err != nil {
			return nil, err
		}
		if m != nil {
			return m, nil
		}
	}
	return nil, nil
}

func findByIDInDB(db *sql.DB, source string, id int64) (*Match, error) {
	table := "mirror_traffic"
	if source == "xray" {
		table = "xray_requests"
	} else if source != "mirror" {
		return nil, nil
	}

	row := db.QueryRow(fmt.Sprintf(`select id, method, url, raw, created_at from %s
		where id = ? limit 1`, table), id)
	var m Match
	m.Source = source
	err := row.Scan(&m.ID, &m.Method, &m.URL, &m.Raw, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (t *DB) findMatchByNeedles(needles []string) (*Match, error) {
	needles = uniqueStrings(needles)
	for _, needle := range needles {
		if m, err := t.findIn("xray_requests", needle); err != nil {
			return nil, err
		} else if m != nil {
			return m, nil
		}
	}
	for _, needle := range needles {
		if m, err := t.findIn("mirror_traffic", needle); err != nil {
			return nil, err
		} else if m != nil {
			return m, nil
		}
	}
	return nil, nil
}

func (t *DB) findIn(table, needle string) (*Match, error) {
	return findInDB(t.db, table, needle)
}

func execWithRetry(db *sql.DB, query string, args ...any) (sql.Result, error) {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		res, err := db.Exec(query, args...)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if !isBusyError(err) {
			return nil, err
		}
		time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
	}
	return nil, lastErr
}

func isBusyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "sqlite_busy") ||
		strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked")
}

func candidateIDs(fullID string) []string {
	fullID = strings.Trim(strings.TrimSpace(fullID), ".")
	if fullID == "" {
		return nil
	}
	if i := strings.IndexByte(fullID, '.'); i > 0 {
		label := fullID[:i]
		if isLikelyCorrelationID(label) {
			return []string{fullID, label}
		}
		return nil
	}
	if isLikelyCorrelationID(fullID) {
		return []string{fullID}
	}
	return nil
}

func isLikelyCorrelationID(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	if len(label) < 8 {
		return false
	}
	switch label {
	case "www", "wwww", "ns1", "ns2", "api", "mail", "smtp", "imap", "pop", "ftp", "cdn", "static", "assets":
		return false
	}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	if !strings.ContainsAny(label, "0123456789") {
		return false
	}
	return strings.Contains(label, "-") || len(label) >= 12
}

func recordRequestTokens(db *sql.DB, source string, requestID int64, values ...string) error {
	tokens := make([]string, 0, 8)
	for _, value := range values {
		tokens = append(tokens, extractRequestTokens(value)...)
	}
	tokens = uniqueStrings(tokens)
	if len(tokens) == 0 {
		return nil
	}
	if len(tokens) > 64 {
		tokens = tokens[:64]
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`insert into request_tokens(token,source,request_id,created_at) values(?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	now := time.Now().Format(time.RFC3339Nano)
	for _, token := range tokens {
		if _, err := stmt.Exec(strings.ToLower(token), source, requestID, now); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func extractRequestTokens(value string) []string {
	original := value
	value = strings.ToLower(value)
	if original == "" {
		return nil
	}
	values := []string{value}
	if decoded, err := url.QueryUnescape(value); err == nil && decoded != value {
		values = []string{strings.ToLower(decoded)}
	}

	out := make([]string, 0, 8)
	for _, candidate := range values {
		out = append(out, extractRequestTokensFromPlainText(candidate)...)
	}
	for _, decoded := range decodeLikelyBase64Values(original) {
		out = append(out, extractRequestTokens(decoded)...)
	}
	return uniqueStrings(out)
}

func decodeLikelyBase64Values(value string) []string {
	const (
		minLen        = 16
		maxLen        = 8192
		maxCandidates = 32
	)

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '_' || r == '-' || r == '=')
	})

	out := make([]string, 0, 4)
	seen := make(map[string]struct{})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) < minLen || len(part) > maxLen {
			continue
		}
		if !looksLikeBase64(part) {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		if len(seen) > maxCandidates {
			break
		}
		if decoded, ok := decodeBase64Text(part); ok {
			decoded = strings.ToLower(decoded)
			out = append(out, decoded)
			if unescaped, err := url.QueryUnescape(decoded); err == nil && unescaped != decoded {
				out = append(out, strings.ToLower(unescaped))
			}
		}
	}
	return uniqueStrings(out)
}

func looksLikeBase64(value string) bool {
	hasPadding := strings.Contains(value, "=")
	hasUpper := false
	for _, r := range value {
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
			break
		}
	}
	return hasPadding || hasUpper || strings.ContainsAny(value, "+/_-")
}

func decodeBase64Text(value string) (string, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(value)
		if err != nil {
			continue
		}
		if isUsefulDecodedText(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

func isUsefulDecodedText(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	printable := 0
	for _, b := range value {
		if b == '\r' || b == '\n' || b == '\t' || (b >= 0x20 && b <= 0x7e) {
			printable++
		}
	}
	if printable*100/len(value) < 85 {
		return false
	}
	text := strings.ToLower(string(value))
	return strings.Contains(text, ".") || strings.Contains(text, "http://") || strings.Contains(text, "https://")
}

func extractRequestTokensFromPlainText(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.')
	})

	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(part, ".")
		if part == "" {
			continue
		}
		if strings.Contains(part, ".") {
			out = append(out, candidateIDs(part)...)
		}
	}
	return uniqueStrings(out)
}

func interactionNeedles(interaction model.OOBInteraction) []string {
	needles := httpInteractionNeedles(interaction.RawRequest)
	needles = append(needles, candidateIDs(interaction.FullID)...)
	return needles
}

func httpInteractionNeedles(raw string) []string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return nil
	}

	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return nil
	}
	path := fields[1]
	if !strings.HasPrefix(path, "/") {
		return nil
	}

	host := ""
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			host = strings.TrimSpace(value)
			break
		}
	}
	if host == "" {
		return nil
	}

	hostPath := strings.TrimRight(host, "/") + path
	withScheme := "http://" + hostPath
	return []string{
		hostPath,
		withScheme,
		url.QueryEscape(withScheme),
		url.QueryEscape(hostPath),
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func rawMirror(req *model.MirrorRequest) string {
	return rawHTTPWithHost(req.Method, req.URL, req.Host, req.Headers, req.Body)
}

func rawHTTP(method, url string, headers map[string][]string, body []byte) string {
	return rawHTTPWithHost(method, url, "", headers, body)
}

func rawHTTPWithHost(method, url, host string, headers map[string][]string, body []byte) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte(' ')
	b.WriteString(url)
	b.WriteString(" HTTP/1.1\r\n")
	hasHost := false
	for k, vals := range headers {
		if strings.EqualFold(k, "Host") {
			hasHost = true
		}
		for _, v := range vals {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	if host != "" && !hasHost {
		b.WriteString("Host: ")
		b.WriteString(host)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// StartRotationTicker 启动定时器，每小时检查一次是否需要滚动db
func (t *DB) StartRotationTicker(logger *slog.Logger) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := t.Rotate(); err != nil {
				logger.Error("traffic db rotation failed", "error", err)
			}
		}
	}()
}
