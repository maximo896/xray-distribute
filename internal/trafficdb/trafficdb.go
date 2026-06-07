package trafficdb

import (
	"database/sql"
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
		`create index if not exists idx_mirror_created_at on mirror_traffic(created_at)`,
		`create index if not exists idx_xray_created_at on xray_requests(created_at)`,
		`create index if not exists idx_oob_full_id on oob_interactions(full_id)`,
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
	return res.LastInsertId()
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
	return res.LastInsertId()
}

func (t *DB) RecordOOB(interaction model.OOBInteraction) (*Match, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// 先在当前db中查找匹配
	match, _ := t.findMatchByNeedles(interactionNeedles(interaction))

	// 如果当前db没找到，跨所有db查找
	if match == nil {
		match, _ = t.findMatchAcrossDBs(interactionNeedles(interaction))
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

	// 先在当前db查找
	if m, err := t.findMatchByNeedles(candidateIDs(fullID)); err != nil {
		return nil, err
	} else if m != nil {
		return m, nil
	}
	// 跨所有db查找
	return t.findMatchAcrossDBs(candidateIDs(fullID))
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
	fullID = strings.TrimSpace(fullID)
	if fullID == "" {
		return nil
	}
	parts := []string{fullID}
	if i := strings.IndexByte(fullID, '.'); i > 0 {
		parts = append(parts, fullID[:i])
	}
	return parts
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
	return rawHTTP(req.Method, req.URL, req.Headers, req.Body)
}

func rawHTTP(method, url string, headers map[string][]string, body []byte) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte(' ')
	b.WriteString(url)
	b.WriteString(" HTTP/1.1\r\n")
	for k, vals := range headers {
		for _, v := range vals {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
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
