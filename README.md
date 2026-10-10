# DIFO — DIsclosure inFOrmation


```bash
difo -d example.com -silent | httpx -silent | naabu | nuclei
```

## Install / Build

Requires Go 1.25+. No external dependencies (pure Go, single static binary).

```bash
go build -o difo .        # produces ./difo (difo.exe on Windows)
go install -v github.com/betillogalvanfbc/difo@latest
```

## Quick start

```bash
# Hunt sensitive files across a target (Wayback, all subdomains)
difo -d example.com

# Use every source, download each distinct archived version, and the live ones
difo -d example.com -sources all -ext js -download -live

# Clean URL stream into a recon pipeline
difo -d example.com -all -silent | httpx -silent -mc 200
```

---

## 1. URL sources


```bash
difo -d example.com -sources all                 # the three of them
difo -d example.com -sources wayback,otx         # a subset
difo -d example.com -sources cc -cc-indexes 5    # 5 newest Common Crawl indexes
```

- **OTX** paginates automatically until exhausted.
- **Common Crawl** reads `collinfo.json`, picks the `-cc-indexes` newest crawl
  indexes and queries each. More indexes = more coverage but slower (its index
  API is frequently slow and may return 504 — DIFO retries and degrades
  cleanly, continuing with whatever else succeeds).

## 2. Decluttering (uro-compatible)

A built-in, in-process reimplementation of `uro`: it drops static assets,
collapses incremental URLs (`/users/123` ≈ `/users/456`), removes blog/doc
content, and dedupes URLs that differ only in query-parameter *values*.
Sensitive hits are **never** dropped by this stage. On by default (`-uro`).

```bash
difo -d example.com -all -uro                    # decluttered full list
difo -d example.com -all -vuln                   # keep only vuln-looking params
difo -d example.com -all -hasparams -b png,jpg   # has params, drop images
```

uro filters: `-w` / `-b` (extension white/blacklist), `-hasparams` `-noparams`
`-hasext` `-noext` `-allexts` `-keepcontent` `-keepslash` `-vuln`.

## 3. Sensitive-file matching

Flags URLs whose extension or path keyword looks sensitive. Override or extend
the built-in lists.

```bash
difo -d example.com                              # default sensitive extensions
difo -d example.com -ext sql,bak,env,config      # only these extensions
difo -d example.com -add-ext js -add-kw dump     # defaults + extras
difo -d example.com -all                         # disable filtering (every URL)
```

**Default extensions:** `xls xlsx xml json sql pptx zip tar tgz docx yaml yml
config cache backup gz bak key dmg iso img pub md md5 sh db bin crt rar node ini
asc dll log exe pem p12 pfx jks keystore csv tsv sqlite dump old orig swp tmp 7z
war jar class properties env htpasswd htaccess`

**Default keywords:** `apikey api_key secret password passwd credential token
backup dump private .git .svn .ds_store id_rsa wp-config web.config .env
dockerfile docker-compose`

## 4. Downloading archived files (versions over time)

`-download` fetches the real content of every finding to disk. Two things make
it correct:

- **Original bytes, not rewritten HTML** — downloads via the Wayback `id_`
  (identity) modifier, so a `.js`, `.exe` or `.xml` comes back exactly as
  archived, with no toolbar or link rewriting.
- **One file per distinct content version** — for each URL, DIFO enumerates all
  captures, filters by status (default `200`), uses the CDX `digest` as a cheap
  first filter, then dedupes by the **SHA1 of the downloaded bytes** so only
  genuinely distinct content is kept (gzip-vs-plain variants collapse). When the
  content is identical across captures, the **newest** one is kept. A file whose
  content actually changed over the years yields every distinct version.

```bash
difo -d example.com -ext js -download                 # every distinct version
difo -d example.com -ext js -download -latest         # only the newest version
difo -d example.com -ext sql,bak -download -max-size 0 -dc 10
```

Saved under `-outdir` (default `loot/`) as:

```
loot/<host>/<url-path>/<timestamp>_<digest8>_<filename>
```

The timestamp + short digest prefix keeps every version side by side.

## 5. Live capture (current assets from the origin)

`-live` fetches the assets the domain serves **right now**, straight from the
live origin — the scriptable equivalent of a browser "resource saver". It loads
the page, follows `<script src>` / stylesheet links, and then **recursively**
follows webpack/Angular chunk maps embedded in `runtime.js`/`main.js` and
`sourceMappingURL` references. Combined with `-download` you get archived +
current side by side.

```bash
difo -d example.com -live                              # js + css + map, same site
difo -d example.com -live -live-assets map             # only hunt sourcemaps
difo -d example.com -live -live-external               # include 3rd-party/CDN hosts (recursive)
difo -d example.com -live -live-max 2000               # raise the crawl cap
```

- Captures `js`, `css` and sourcemaps (`.map`) by default (`-live-assets`).
- `.map` sourcemaps often contain the original source in `sourcesContent` —
  useful for reconstructing the pre-build code.
- `-live-external` follows third-party CDNs recursively (bounded by `-live-max`,
  default 1000).
- Saved under `loot/<host>/_live/...` with the capture timestamp.

> Live capture is static HTTP: it covers statically-referenced assets and
> webpack/Angular chunks. Assets built by runtime JS execution or fetched via
> dynamic XHR need a real browser to capture.

## 6. Snapshots (the 404 fix)

When a live file 404s, `-snapshot` resolves the closest archived capture via the
availability API and prints a working `web.archive.org` URL for each finding.

```bash
difo -d example.com -snapshot -c 30
```

## 7. Rate limiting & reliability

The Internet Archive and Common Crawl rate-limit (429) and time out (504/503).
DIFO retries automatically with exponential backoff and jitter, honoring
`Retry-After`, and a failing source never aborts the run.

```bash
difo -d example.com -retries 6 -retry-base 5           # wait longer
difo -d example.com -delay 500 -dc 2 -c 5              # gentler: delay + low concurrency
```

## 8. Output & piping

- **stdout** — plain result URLs, one per line, line-flushed (pipe-friendly).
  With `-json`, one JSON object per line. With `-all`, every decluttered URL.
- **stderr** — banner, progress, colored findings, summary. Silenced by
  `-silent`; colors auto-disable when piped or with `-no-color` / `NO_COLOR`.
- **stdin** — when no domain is given, targets are read from stdin.

```bash
cat scope.txt | difo -sources all -silent | httpx -silent | nuclei
difo -d example.com -silent -o hits.txt -dump all.txt
echo example.com | difo -all -silent | anew urls.txt
```

---

## All options

| Flag | Description |
|------|-------------|
| `-d <domain>` | Single target domain |
| `-l <file>` | File with one domain per line |
| `-sources <list>` | `wayback,otx,commoncrawl` or `all` (default `wayback`) |
| `-cc-indexes <n>` | Recent Common Crawl indexes to query (default `3`) |
| `-subs` | Include subdomains `*.domain` (default `true`) |
| `-collapse <field>` | CDX collapse field (default `urlkey`) |
| `-mt <type>` | CDX `matchType`: `exact\|prefix\|host\|domain` |
| `-limit <n>` | Max results (0 = no limit) |
| `-from` / `-to` | Capture date range `YYYYMMDD` |
| `-ext <list>` | Override sensitive extensions |
| `-add-ext <list>` | Add extensions to the defaults |
| `-kw <list>` | Override sensitive keywords |
| `-add-kw <list>` | Add keywords to the defaults |
| `-all` | Output every URL instead of only sensitive ones |
| `-uro` | Declutter results (default `true`) |
| `-w` / `-b` | uro extension whitelist / blacklist |
| `-hasparams` `-noparams` `-hasext` `-noext` `-allexts` `-keepcontent` `-keepslash` `-vuln` | uro filters |
| `-download` | Download archived file content for each finding |
| `-outdir <dir>` | Directory to save downloads (default `loot`) |
| `-status <list>` | CDX status filter for downloads: `200`, `200,301`, `any` |
| `-max-size <MB>` | Max size per downloaded file (`0` = unlimited, default `25`) |
| `-latest` | Download only the newest version |
| `-dc <n>` | Concurrency for downloads (default `5`) |
| `-live` | Download the domain's current assets from the live origin |
| `-live-assets <list>` | Live asset types: `js,css,map` (default all) |
| `-live-external` | Include third-party/external asset hosts (recursive) |
| `-live-max <n>` | Max assets in the recursive live crawl (default `1000`) |
| `-snapshot` | Resolve the closest Wayback snapshot per finding |
| `-c <n>` | Concurrency for snapshot resolution (default `20`) |
| `-o <file>` | Write findings (URLs) to a file |
| `-dump <file>` | Write the full URL list to a file |
| `-json` | Emit findings as JSON lines |
| `-silent` | Only print result URLs to stdout |
| `-no-color` | Disable ANSI colors |
| `-retries <n>` | Retries on HTTP 429/5xx (default `4`) |
| `-retry-base <s>` | Base backoff seconds, doubles each retry (default `2`) |
| `-delay <ms>` | Polite delay before each request |
| `-timeout <s>` | HTTP timeout in seconds (default `60`) |
| `-ua <string>` | Custom User-Agent |
| `-version` | Print version |
