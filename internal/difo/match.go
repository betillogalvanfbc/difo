package difo

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// DefaultExtensions is the built-in list of file extensions worth hunting for
// when looking for information disclosure in archived URLs.
var DefaultExtensions = []string{
	"xls", "xlsx", "xml", "json", "sql", "pptx", "zip", "tar", "tgz", "docx",
	"yaml", "yml", "config", "cache", "backup", "gz", "bak", "key", "dmg",
	"iso", "img", "pub", "md", "md5", "sh", "db", "bin", "crt", "rar", "node",
	"ini", "asc", "dll", "log", "exe", "pem", "p12", "pfx", "jks", "keystore",
	"csv", "tsv", "sqlite", "sqlitedb", "dump", "old", "orig", "swp", "tmp",
	"7z", "war", "jar", "class", "properties", "env", "htpasswd", "htaccess",
}

// DefaultKeywords is the built-in list of substrings that often indicate
// sensitive content regardless of extension.
var DefaultKeywords = []string{
	"apikey", "api_key", "api-key", "secret", "password", "passwd", "credential",
	"token", "backup", "dump", "private", ".git", ".svn", ".ds_store", "id_rsa",
	"id_dsa", "wp-config", "web.config", ".env", "dockerfile", "docker-compose",
}

// Matcher decides whether a URL is interesting based on file extensions and
// substring keywords.
type Matcher struct {
	extRe    *regexp.Regexp
	keywords []string
	all      bool // when true, every URL matches
}

// NewMatcher builds a Matcher from extensions and keywords. When matchAll is
// true the matcher returns true for every URL (filtering disabled).
func NewMatcher(exts, keywords []string, matchAll bool) *Matcher {
	m := &Matcher{all: matchAll}

	if len(exts) > 0 {
		quoted := make([]string, 0, len(exts))
		for _, e := range exts {
			e = strings.TrimSpace(strings.TrimPrefix(e, "."))
			if e == "" {
				continue
			}
			quoted = append(quoted, regexp.QuoteMeta(e))
		}
		if len(quoted) > 0 {
			// Match .ext at the end of the path or right before a query/fragment.
			pattern := `(?i)\.(` + strings.Join(quoted, "|") + `)($|[?#])`
			m.extRe = regexp.MustCompile(pattern)
		}
	}

	for _, k := range keywords {
		k = strings.TrimSpace(k)
		if k != "" {
			m.keywords = append(m.keywords, strings.ToLower(k))
		}
	}
	return m
}

// Match reports whether rawURL is interesting, and if so which label (the
// extension or keyword) caused the hit.
func (m *Matcher) Match(rawURL string) (bool, string) {
	if m.all {
		return true, "all"
	}

	// Extension check runs against the path only, so query strings carrying a
	// lookalike value do not create false positives.
	target := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		target = u.Path
	}

	if m.extRe != nil {
		if sm := m.extRe.FindStringSubmatch(target); sm != nil {
			return true, strings.ToLower(sm[1])
		}
	}

	lower := strings.ToLower(rawURL)
	for _, k := range m.keywords {
		if strings.Contains(lower, k) {
			return true, k
		}
	}
	return false, ""
}

// Ext returns the lower-cased file extension of a URL's path, or "" if none.
func Ext(rawURL string) string {
	u, err := url.Parse(rawURL)
	p := rawURL
	if err == nil && u.Path != "" {
		p = u.Path
	}
	e := strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))
	return e
}
