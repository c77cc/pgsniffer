package pgsql

import "testing"

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{name: "literals", query: "SELECT * FROM users WHERE id = 42 AND name = 'Alice'", want: "select * from users where id = ? and name = ?"},
		{name: "escaped string", query: "select 'it''s fine', 12.5", want: "select ?, ?"},
		{name: "parameters", query: "SELECT * FROM t WHERE id=$1", want: "select * from t where id=$1"},
		{name: "comments", query: "SELECT /* private */ 1 -- tail\nFROM t", want: "select ? from t"},
		{name: "quoted identifier", query: `SELECT "CamelCase" FROM "User"`, want: `select "CamelCase" from "User"`},
		{name: "dollar quote", query: "SELECT $tag$secret$tag$", want: "select ?"},
		{name: "unicode identifier", query: "SELECT 名称 FROM 用户", want: "select 名称 from 用户"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Fingerprint(test.query); got != test.want {
				t.Fatalf("Fingerprint(%q) = %q, want %q", test.query, got, test.want)
			}
		})
	}
}

func FuzzFingerprint(f *testing.F) {
	f.Add("SELECT * FROM users WHERE id = 42")
	f.Add("SELECT $tag$hello$tag$, 'world'")
	f.Fuzz(func(t *testing.T, query string) {
		_ = Fingerprint(query)
	})
}
