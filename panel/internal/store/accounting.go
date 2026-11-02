package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func validateSetting(key, value string) error {
	switch key {
	case "traffic_rate":
		if _, err := trafficRate(value); err != nil {
			return err
		}
	case "quota_reset_day":
		d, err := strconv.Atoi(value)
		if err != nil || d < 0 || d > 28 {
			return fmt.Errorf("quota_reset_day must be 0..28")
		}
	case "alert_webhook", "sub_base":
		if value == "" {
			return nil
		}
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("invalid HTTP(S) URL")
		}
		if key == "sub_base" && u.RawQuery != "" {
			return fmt.Errorf("sub_base cannot contain a query")
		}
	case "extra_config":
		var object map[string]any
		if json.Unmarshal([]byte(value), &object) != nil || object == nil {
			return fmt.Errorf("extra_config must be a JSON object")
		}
	case "sub_host", "sub_title":
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("setting cannot contain newlines")
		}
	default:
		return fmt.Errorf("unsupported setting %q", key)
	}
	return nil
}

func (s *Store) initAccounting() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS traffic_hourly (hour INTEGER NOT NULL,user_name TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(hour,user_name));
CREATE TABLE IF NOT EXISTS traffic_remainders (source TEXT NOT NULL,user_name TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(source,user_name));
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY,at INTEGER NOT NULL,kind TEXT NOT NULL,user_name TEXT NOT NULL,message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS usage_state (user_name TEXT PRIMARY KEY,state TEXT NOT NULL);
`)
	return err
}

// Reset only the billed cycle, never the raw cumulative checkpoints or history.
// First activation records a baseline instead of wiping existing usage.
func (s *Store) ResetMonthly(now time.Time) (bool, error) {
	day, err := strconv.Atoi(s.Setting("quota_reset_day", "0"))
	if err != nil || day < 0 || day > 28 {
		return false, fmt.Errorf("invalid quota reset day")
	}
	if day == 0 {
		return false, nil
	}
	due := time.Date(now.Year(), now.Month(), day, 0, 0, 0, 0, now.Location())
	if due.After(now) {
		due = due.AddDate(0, -1, 0)
	}
	cycle := due.Format("2006-01-02")
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var previous string
	err = tx.QueryRow("SELECT value FROM settings WHERE key='quota_last_reset'").Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	changed := previous != "" && previous < cycle
	if previous >= cycle {
		return false, nil
	}
	if changed {
		if _, err = tx.Exec("DELETE FROM traffic"); err != nil {
			return false, err
		}
		if _, err = tx.Exec("DELETE FROM usage_state"); err != nil {
			return false, err
		}
		if _, err = tx.Exec("DELETE FROM traffic_remainders"); err != nil {
			return false, err
		}
		if _, err = tx.Exec("INSERT INTO events(at,kind,user_name,message) VALUES(?,?,?,?)", now.Unix(), "reset", "", "monthly usage reset"); err != nil {
			return false, err
		}
	}
	if _, err = tx.Exec("INSERT INTO settings(key,value) VALUES('quota_last_reset',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", cycle); err != nil {
		return false, err
	}
	return changed, tx.Commit()
}

type TrafficPoint struct {
	Hour int64 `json:"hour"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func (s *Store) TrafficHistory(now time.Time, hours int) ([]TrafficPoint, error) {
	if hours < 1 || hours > 720 {
		return nil, fmt.Errorf("hours must be 1..720")
	}
	last := now.Truncate(time.Hour).Unix()
	first := last - int64(hours-1)*3600
	result := make([]TrafficPoint, hours)
	for i := range result {
		result[i].Hour = first + int64(i)*3600
	}
	rows, err := s.db.Query("SELECT hour,SUM(up),SUM(down) FROM traffic_hourly WHERE hour>=? AND hour<=? GROUP BY hour ORDER BY hour", first, last)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p TrafficPoint
		if err = rows.Scan(&p.Hour, &p.Up, &p.Down); err != nil {
			return nil, err
		}
		index := (p.Hour - first) / 3600
		if index >= 0 && index < int64(len(result)) {
			result[index] = p
		}
	}
	return result, rows.Err()
}

type Event struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"`
	Kind    string `json:"kind"`
	User    string `json:"user"`
	Message string `json:"message"`
}

func (s *Store) Event(kind, user, message string) error {
	_, err := s.db.Exec("INSERT INTO events(at,kind,user_name,message) VALUES(?,?,?,?)", time.Now().Unix(), kind, user, message)
	return err
}
func (s *Store) Events(limit int) ([]Event, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("limit must be 1..1000")
	}
	rows, err := s.db.Query("SELECT id,at,kind,user_name,message FROM events ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Event{}
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.At, &e.Kind, &e.User, &e.Message); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// State transitions, rather than every poll, produce notifications.
func (s *Store) UsageEvents(now time.Time) ([]Event, error) {
	users, err := s.Users()
	if err != nil {
		return nil, err
	}
	usage, err := s.AllUsage()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result := []Event{}
	for _, u := range users {
		state := "ok"
		v := usage[u.Name]
		used := v[0] + v[1]
		switch {
		case !u.Enabled:
			state = "disabled"
		case u.ExpiresAt > 0 && now.Unix() >= u.ExpiresAt:
			state = "expired"
		case u.QuotaBytes > 0 && used >= u.QuotaBytes:
			state = "over_quota"
		case u.QuotaBytes > 0 && used >= u.QuotaBytes-u.QuotaBytes/5:
			state = "warning"
		}
		var previous string
		err = tx.QueryRow("SELECT state FROM usage_state WHERE user_name=?", u.Name).Scan(&previous)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if state == previous {
			continue
		}
		if _, err = tx.Exec("INSERT INTO usage_state(user_name,state) VALUES(?,?) ON CONFLICT(user_name) DO UPDATE SET state=excluded.state", u.Name, state); err != nil {
			return nil, err
		}
		if state == "ok" && previous == "" {
			continue
		}
		e := Event{At: now.Unix(), Kind: state, User: u.Name, Message: fmt.Sprintf("%s: %d / %d bytes", state, used, u.QuotaBytes)}
		res, err := tx.Exec("INSERT INTO events(at,kind,user_name,message) VALUES(?,?,?,?)", e.At, e.Kind, e.User, e.Message)
		if err != nil {
			return nil, err
		}
		e.ID, _ = res.LastInsertId()
		result = append(result, e)
	}
	if _, err = tx.Exec("DELETE FROM events WHERE at<?", now.AddDate(0, 0, -90).Unix()); err != nil {
		return nil, err
	}
	return result, tx.Commit()
}

const rateScale int64 = 1_000_000

func trafficRate(value string) (int64, error) {
	r, ok := new(big.Rat).SetString(value)
	if !ok || r.Sign() <= 0 || r.Cmp(big.NewRat(1000, 1)) > 0 {
		return 0, fmt.Errorf("traffic_rate must be >0 and <=1000")
	}
	r.Mul(r, big.NewRat(rateScale, 1))
	if !r.IsInt() {
		return 0, fmt.Errorf("traffic_rate supports at most six decimal places")
	}
	return r.Num().Int64(), nil
}

// Fixed-point arithmetic preserves both large counters and sub-byte deltas.
func scaledDelta(delta, rate, remainder int64) (int64, int64, error) {
	if delta < 0 || rate <= 0 || rate > 1000*rateScale || remainder < 0 || remainder >= rateScale {
		return 0, 0, fmt.Errorf("invalid traffic rate or remainder")
	}
	whole, fraction := delta/rateScale, (delta%rateScale)*rate+remainder
	if whole > (math.MaxInt64-fraction/rateScale)/rate {
		return 0, 0, fmt.Errorf("billed traffic overflow")
	}
	return whole*rate + fraction/rateScale, fraction % rateScale, nil
}
