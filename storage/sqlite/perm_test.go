package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// 新しく作る DB のファイルは持ち主だけが読み書きできる。
func TestOpenCreatesPrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("権限の形が違う")
	}
	for _, name := range []string{"mdm.db", "a b#c?d%20e.db"} {
		checkPrivate(t, filepath.Join(t.TempDir(), name))
	}
}

func checkPrivate(t *testing.T, path string) {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// 開いたのが作ったファイルそのもの（予約文字のある名前でも別のファイルを作らない）。
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if n := e.Name(); n != filepath.Base(path) && n != filepath.Base(path)+"-wal" && n != filepath.Base(path)+"-shm" {
			t.Errorf("別のファイルができた: %q", n)
		}
	}
	for _, p := range []string{path, path + "-wal"} {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: %v", p, fi.Mode().Perm())
		}
	}
}
