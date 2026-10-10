package difo

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// ANSI color codes. Disabled automatically when output is not a terminal or
// NO_COLOR is set.
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cPurple = "\033[35m"
	cCyan   = "\033[36m"
	cGray   = "\033[90m"
)

// UI centralizes all human-facing (stderr) output and coloring.
type UI struct {
	w     io.Writer
	color bool
}

// NewUI returns a UI writing status messages to stderr. Color is enabled unless
// disabled explicitly, NO_COLOR is set, or stderr is not a terminal.
func NewUI(forceNoColor bool) *UI {
	enabled := !forceNoColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stderr)
	return &UI{w: os.Stderr, color: enabled}
}

func (u *UI) paint(code, s string) string {
	if !u.color {
		return s
	}
	return code + s + cReset
}

func (u *UI) Info(format string, a ...any) {
	fmt.Fprintf(u.w, u.paint(cCyan, "[*] ")+format+"\n", a...)
}

func (u *UI) Good(format string, a ...any) {
	fmt.Fprintf(u.w, u.paint(cGreen, "[+] ")+format+"\n", a...)
}

func (u *UI) Warn(format string, a ...any) {
	fmt.Fprintf(u.w, u.paint(cYellow, "[!] ")+format+"\n", a...)
}

func (u *UI) Err(format string, a ...any) {
	fmt.Fprintf(u.w, u.paint(cRed, "[x] ")+format+"\n", a...)
}

func (u *UI) Dim(format string, a ...any) {
	fmt.Fprintf(u.w, u.paint(cGray, format)+"\n", a...)
}

// Hit prints a single finding to stderr with the matched label highlighted.
func (u *UI) Hit(label, rawURL string) {
	fmt.Fprintf(u.w, "%s %s %s\n",
		u.paint(cRed+cBold, "[!]"),
		u.paint(cYellow, fmt.Sprintf("%-10s", label)),
		rawURL,
	)
}

// Snapshot prints a resolved snapshot line beneath a finding.
func (u *UI) SnapshotLine(s Snapshot) {
	if s.Available && s.URL != "" {
		fmt.Fprintf(u.w, "    %s %s %s\n",
			u.paint(cGreen, "└─ snapshot"),
			u.paint(cDim, s.Timestamp),
			u.paint(cBlue, s.URL),
		)
	} else {
		fmt.Fprintf(u.w, "    %s\n", u.paint(cGray, "└─ no snapshot available"))
	}
}

// Saved prints a line for a downloaded archived file.
func (u *UI) Saved(timestamp string, size int64, dest string) {
	fmt.Fprintf(u.w, "    %s %s %s %s\n",
		u.paint(cGreen, "└─ saved"),
		u.paint(cDim, timestamp),
		u.paint(cCyan, fmt.Sprintf("(%d B)", size)),
		u.paint(cBlue, dest),
	)
}

// Banner prints the DIFO ASCII banner.
func (u *UI) Banner(version string) {
	art := `
   ___  _________
  / _ \/  _/ __/__
 / // // // _// _ \
/____/___/_/  \___/   DIFO · inFOrmation DIsclosure 
`
	fmt.Fprint(u.w, u.paint(cPurple+cBold, art))
	fmt.Fprintf(u.w, "%s\n\n", u.paint(cGray, "   v"+version+" · inFOrmation DIsclosure "))
}

// isTerminal reports whether f looks like an interactive terminal. On Windows
// we keep it simple and assume a terminal unless redirected; Go's os.Stderr is
// a *os.File so we can at least check that it is a character device.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		// Good enough heuristic: modern Windows terminals support ANSI and a
		// redirected handle reports a regular file.
		return (fi.Mode() & os.ModeCharDevice) != 0
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
