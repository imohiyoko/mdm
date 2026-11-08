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
	path := filepath.Join(t.TempDir(), "mdm.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
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
