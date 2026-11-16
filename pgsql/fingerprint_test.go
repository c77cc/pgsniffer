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
		{name: "parameters", query: "SELECT * FROM t WHERE id=$1", want: "select * from t where id = $1"},
		{name: "comments", query: "SELECT /* private */ 1 -- tail\nFROM t", want: "select ? from t"},
		{name: "nested comments", query: "SELECT /* outer /* inner */ hidden */ 1", want: "select ?"},
		{name: "quoted identifier", query: `SELECT "CamelCase" FROM "User"`, want: `select "CamelCase" from "User"`},
		{name: "unicode quoted identifier", query: `SELECT U&"d\\0061t" FROM foo$bar`, want: `select u&"d\\0061t" from foo$bar`},
		{name: "dollar quote", query: "SELECT $tag$secret$tag$", want: "select ?"},
		{name: "prefixed strings", query: `SELECT E'line\\n', B'101', X'ff', U&'d\\0061t'`, want: "select ?, ?, ?, ?"},
		{name: "literal keywords", query: "SELECT TRUE, false, NULL", want: "select ?, ?, ?"},
		{name: "canonical formatting", query: " SELECT a,b FROM t WHERE id=1::bigint; ", want: "select a, b from t where id = ?::bigint"},
		{name: "numeric operators", query: "SELECT 1-2, 1e-3, .5, 0xFF", want: "select ? - ?, ?, ?, ?"},
		{name: "in list", query: "SELECT * FROM t WHERE id IN (1, 2, $3)", want: "select * from t where id in (?)"},
		{name: "in subquery preserved", query: "SELECT * FROM t WHERE id IN (SELECT id FROM x)", want: "select * from t where id in (select id from x)"},
		{name: "array list", query: "SELECT ARRAY[1, 2, 3]", want: "select array[?]"},
		{name: "batch values", query: "INSERT INTO t(a,b) VALUES (1,'a'), (2,'b'), (3,'c') RETURNING id", want: "insert into t (a, b) values (?, ?), ... returning id"},
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

func TestFingerprintGroupsEquivalentSQL(t *testing.T) {
	tests := [][]string{
		{"SELECT * FROM t WHERE id=1", " select  *  from t where id = 999;", "SELECT/* comment */* FROM t WHERE id=42"},
		{"SELECT * FROM t WHERE id IN (1)", "SELECT * FROM t WHERE id IN (1,2,3)", "SELECT * FROM t WHERE id IN ($1,$2)"},
		{"INSERT INTO t(a,b) VALUES (1,'a'),(2,'b')", "insert into t (a, b) values (9, 'x'), (8, 'y'), (7, 'z')"},
	}
	for _, group := range tests {
		want := Fingerprint(group[0])
		for _, query := range group[1:] {
			if got := Fingerprint(query); got != want {
				t.Errorf("Fingerprint(%q) = %q, want %q from %q", query, got, want, group[0])
			}
		}
	}
}

func FuzzFingerprint(f *testing.F) {
	f.Add("SELECT * FROM users WHERE id = 42")
	f.Add("SELECT $tag$hello$tag$, 'world'")
	f.Fuzz(func(t *testing.T, query string) {
		_ = Fingerprint(query)
	})
}
