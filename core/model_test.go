package core

import (
	"testing"
	"time"
)

func at(day time.Weekday, hh, mm int) time.Time {
	// 2026-11-01 は日曜日。
	return time.Date(2026, 11, 1+int(day), hh, mm, 0, 0, time.UTC)
}

func TestWindowContains(t *testing.T) {
	night := Window{Start: 21 * 60, End: 7 * 60}
	school := Window{Days: []time.Weekday{time.Monday}, Start: 9 * 60, End: 15 * 60}
	friNight := Window{Days: []time.Weekday{time.Friday}, Start: 23 * 60, End: 6 * 60}
	cases := []struct {
		name string
		w    Window
		t    time.Time
		want bool
	}{
		{"夜の始まり", night, at(time.Monday, 21, 0), true},
		{"夜の前", night, at(time.Monday, 20, 59), false},
		{"夜中", night, at(time.Tuesday, 3, 0), true},
		{"朝の終わりは含まない", night, at(time.Tuesday, 7, 0), false},
		{"月曜の授業中", school, at(time.Monday, 10, 0), true},
		{"火曜は当たらない", school, at(time.Tuesday, 10, 0), false},
		{"金曜の夜", friNight, at(time.Friday, 23, 30), true},
		{"金曜から続く土曜の朝", friNight, at(time.Saturday, 5, 0), true},
		{"土曜の夜は当たらない", friNight, at(time.Saturday, 23, 30), false},
		{"木曜から続く金曜の朝は当たらない", friNight, at(time.Friday, 5, 0), false},
		{"同じ時刻は空", Window{Start: 60, End: 60}, at(time.Monday, 1, 0), false},
	}
	for _, c := range cases {
		if got := c.w.Contains(c.t); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestFilterToken(t *testing.T) {
	tok, hash := NewFilterToken()
	if !LooksLikeFilterToken(tok) {
		t.Fatalf("形が違う: %q", tok)
	}
	if string(HashFilterToken(tok)) != string(hash) {
		t.Fatal("ハッシュが一致しない")
	}
	// DNS のラベルは大文字・小文字を区別しない。
	upper := []byte(tok)
	for i, c := range upper {
		if c >= 'a' && c <= 'z' {
			upper[i] = c - 32
		}
	}
	if string(HashFilterToken(string(upper))) != string(hash) {
		t.Fatal("大文字でも同じ端末に当たるべき")
	}
	if LooksLikeFilterToken(tok[:31]) || LooksLikeFilterToken(tok[:31]+"1") {
		t.Fatal("形の確認が甘い")
	}
}
