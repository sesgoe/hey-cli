//go:build unix

package cmd

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/basecamp/hey-cli/internal/apierr"
)

// runRestricted runs the restricted build against handler, the way ExecuteRestricted
// would: the server is the one base URL it allows, reached without --base-url.
func runRestricted(t *testing.T, handler http.Handler, args ...string) (string, error) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	t.Setenv("HEY_TOKEN", "test-token")
	t.Setenv("HEY_NO_KEYRING", "1")
	t.Setenv("HEY_BASE_URL", server.URL)
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("XDG_STATE_HOME", tmpDir)
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	previous := restrictedBaseURL
	restrictedBaseURL = server.URL
	t.Cleanup(func() {
		restrictedBaseURL = previous
		draftSavedHook = nil
	})

	root := newRestrictedRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"--json"}, args...))
	err := root.Execute()
	return buf.String(), err
}

func requireForbidden(t *testing.T, err error) {
	t.Helper()
	var cliErr *apierr.Error
	if !errors.As(err, &cliErr) || cliErr.Code != apierr.CodeForbidden {
		t.Fatalf("err = %v, want a forbidden refusal", err)
	}
}

func refuseEveryRequest(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
}

func restrictedCommandPaths(cmd *cobra.Command) []string {
	paths := []string{cmd.CommandPath()}
	for _, sub := range cmd.Commands() {
		paths = append(paths, restrictedCommandPaths(sub)...)
	}
	return paths
}

// Every line of restricted.surface must name something upstream still has, so a
// rename upstream shows up here instead of silently shrinking the build.
func TestRestrictedSurfaceNamesOnlyRealCommandsAndFlags(t *testing.T) {
	full := newRootCmd()
	if attachment, _, err := full.Find([]string{"attachment"}); err == nil {
		attachment.AddCommand(newAttachmentGetCommand())
	}
	real := map[string]bool{}
	for _, line := range collectSurface(full, "") {
		real[line] = true
	}
	for _, extra := range restrictedExtras {
		real[extra] = true
	}
	for line := range restrictedSurface() {
		if !real[line] {
			t.Errorf("restricted.surface lists %q, which the CLI no longer has", line)
		}
	}
}

func TestRestrictedTreeIsExactlyTheAllowlist(t *testing.T) {
	root := newRestrictedRootCmd()
	allowed := restrictedSurface()
	got := map[string]bool{}
	for _, path := range restrictedCommandPaths(root) {
		got[path] = true
		if !allowed[path] {
			t.Errorf("restricted build has %q, which is not on the allowlist", path)
		}
	}
	for line := range allowed {
		if !strings.Contains(line, " --") && !got[line] {
			t.Errorf("allowlist names %q, but the restricted build lost it", line)
		}
	}
}

// Only the root's PersistentPreRunE enforces the policy; cobra would run a nearer
// one instead of it.
func TestRestrictedCommandsCannotBypassThePolicyHook(t *testing.T) {
	root := newRestrictedRootCmd()
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		for _, sub := range cmd.Commands() {
			if sub.PersistentPreRunE != nil || sub.PersistentPreRun != nil {
				t.Errorf("%s has its own persistent pre-run, which would skip the restricted policy", sub.CommandPath())
			}
			walk(sub)
		}
	}
	walk(root)
}

func TestRestrictedBuildHasNoWayToSendOrLeak(t *testing.T) {
	root := newRestrictedRootCmd()
	allowed := restrictedSurface()
	for _, path := range [][]string{
		{"draft", "send"}, {"forward"}, {"bulk-reply"}, {"share"}, {"unshare"},
		{"screener"}, {"contact", "deliver"}, {"contact", "add"}, {"contact", "update"},
		{"auth"}, {"login"}, {"logout"}, {"config"}, {"upgrade"}, {"watch"}, {"mcp"},
		{"setup"}, {"skill"}, {"tui"}, {"attachment", "save"}, {"timetrack", "export"}, {"snippet"},
	} {
		if found, _, err := root.Find(path); err == nil && found != root && found.CommandPath() == "hey "+strings.Join(path, " ") {
			t.Errorf("restricted build still has hey %s", strings.Join(path, " "))
		}
	}
	for _, flag := range []string{
		"hey --base-url", "hey --jq", "hey --account", "hey --verbose",
		"hey compose --attach", "hey reply --attach",
		"hey event add --invite", "hey event edit --invite",
	} {
		if allowed[flag] {
			t.Errorf("allowlist includes %s", flag)
		}
	}
}

func TestRestrictedRefusesUnlistedFlagsBeforeAnyRequest(t *testing.T) {
	for _, args := range [][]string{
		{"compose", "--subject", "x", "-m", "y", "--attach", "/etc/passwd"},
		{"box", "list", "--base-url", "https://attacker.example"},
		{"box", "list", "--jq", "$ENV"},
		{"event", "add", "Lunch", "--starts-on", "2026-10-01", "--invite", "someone@example.com"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, err := runRestricted(t, refuseEveryRequest(t), args...)
			if err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

func TestRestrictedRefusesAServerItWasNotBuiltFor(t *testing.T) {
	server := httptest.NewServer(refuseEveryRequest(t))
	t.Cleanup(server.Close)
	t.Setenv("HEY_TOKEN", "test-token")
	t.Setenv("HEY_NO_KEYRING", "1")
	t.Setenv("HEY_BASE_URL", server.URL)
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("XDG_STATE_HOME", tmpDir)
	t.Setenv("XDG_CACHE_HOME", tmpDir)
	t.Cleanup(func() { draftSavedHook = nil })

	root := newRestrictedRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--json", "box", "list"})
	requireForbidden(t, root.Execute())
}

func TestRestrictedComposeAlwaysSavesADraft(t *testing.T) {
	for _, extra := range [][]string{nil, {"--draft=false"}} {
		var writes []draftWrite
		_, err := runRestricted(t, draftLifecycleServer(t, draftEditJSON, &writes),
			append([]string{"compose", "--to", "maria@example.com", "--subject", "Hi", "-m", "Hello."}, extra...)...)
		if err != nil {
			t.Fatalf("compose %v: %v", extra, err)
		}
		if len(writes) != 1 {
			t.Fatalf("writes = %+v", writes)
		}
		entry, _ := writes[0].Body["entry"].(map[string]any)
		if entry["status"] != "drafted" {
			t.Errorf("compose %v: entry.status = %v, want drafted", extra, entry["status"])
		}
	}
}

func TestRestrictedDraftEditOnlyTouchesItsOwnDrafts(t *testing.T) {
	var writes []draftWrite
	_, err := runRestricted(t, draftLifecycleServer(t, draftEditJSON, &writes), "draft", "edit", "12345", "-m", "changed")
	requireForbidden(t, err)
	if len(writes) != 0 {
		t.Fatalf("a refused edit wrote %+v", writes)
	}

	// The same state directory: a draft this build saved is its own to edit.
	stateDir := t.TempDir()
	handler := draftLifecycleServer(t, draftEditJSON, &writes)
	run := func(args ...string) error {
		t.Helper()
		server := httptest.NewServer(handler)
		defer server.Close()
		t.Setenv("HEY_BASE_URL", server.URL)
		t.Setenv("XDG_STATE_HOME", stateDir)
		restrictedBaseURL = server.URL
		root := newRestrictedRootCmd()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs(append([]string{"--json"}, args...))
		return root.Execute()
	}
	t.Setenv("HEY_TOKEN", "test-token")
	t.Setenv("HEY_NO_KEYRING", "1")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	previous := restrictedBaseURL
	t.Cleanup(func() { restrictedBaseURL = previous; draftSavedHook = nil })

	if err := run("compose", "--subject", "Board update", "-m", "Numbers to follow."); err != nil {
		t.Fatalf("compose: %v", err)
	}
	if err := run("draft", "edit", "12345", "-m", "Numbers attached."); err != nil {
		t.Fatalf("editing its own draft: %v", err)
	}
	if last := writes[len(writes)-1]; last.Method != http.MethodPut {
		t.Errorf("last write = %+v, want the draft update", last)
	} else if entry, _ := last.Body["entry"].(map[string]any); entry["status"] != "drafted" {
		t.Errorf("draft edit wrote status %v, want drafted", entry["status"])
	}
}

func TestRestrictedLeavesAScheduledDraftAlone(t *testing.T) {
	scheduled := strings.Replace(draftEditJSON, `"updated_at"`, `"scheduled_delivery_at":"2026-10-01T15:00:00Z","updated_at"`, 1)
	var writes []draftWrite
	handler := draftLifecycleServer(t, scheduled, &writes)
	if err := recordOwnedDraftIn(t, 12345); err != nil {
		t.Fatal(err)
	}
	_, err := runRestrictedKeepingState(t, handler, "draft", "delete", "12345")
	requireForbidden(t, err)
	if len(writes) != 0 {
		t.Errorf("a scheduled draft was written: %+v", writes)
	}
}

// recordOwnedDraftIn and runRestrictedKeepingState share one state directory.
func recordOwnedDraftIn(t *testing.T, id int64) error {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	return recordOwnedDraft(id)
}

func runRestrictedKeepingState(t *testing.T, handler http.Handler, args ...string) (string, error) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv("HEY_TOKEN", "test-token")
	t.Setenv("HEY_NO_KEYRING", "1")
	t.Setenv("HEY_BASE_URL", server.URL)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	previous := restrictedBaseURL
	restrictedBaseURL = server.URL
	t.Cleanup(func() { restrictedBaseURL = previous; draftSavedHook = nil })

	root := newRestrictedRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"--json"}, args...))
	err := root.Execute()
	return buf.String(), err
}

// calendarServer serves two calendars, Work (9) and Family (12), each with the recordings
// given, and counts every delete it is sent.
func calendarServer(t *testing.T, work, family string, deleted *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/calendars.json":
			_, _ = io.WriteString(w, `{"calendars":[{"calendar":{"id":9,"name":"Work","owned":true}},{"calendar":{"id":12,"name":"Family","owned":true}}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/calendars/9/recordings.json":
			_, _ = io.WriteString(w, work)
		case r.Method == http.MethodGet && r.URL.Path == "/calendars/12/recordings.json":
			_, _ = io.WriteString(w, family)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/calendar/events/4821"):
			deleted.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request = %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	})
}

const (
	dentist       = `{"Calendar::Event":[{"id":4821,"type":"Calendar::Event","title":"Dentist","starts_at":"2026-10-01T12:00:00Z","ends_at":"2026-10-01T13:00:00Z"}]}`
	designReview  = `{"Calendar::Event":[{"id":4821,"type":"Calendar::Event","title":"Design review","starts_at":"2026-10-01T12:00:00Z","ends_at":"2026-10-01T13:00:00Z","attendances":[{"id":1,"email_address":"alice@example.com","status":"accepted"}]}]}`
	weeklyRun     = `{"Calendar::Event":[{"id":4821,"parent_id":4821,"occurrence_id":"4821_2026-10-08","type":"Calendar::Event","title":"Morning run","recurring":true,"starts_at":"2026-10-08T11:00:00Z","ends_at":"2026-10-08T12:00:00Z"}]}`
	runWithGuests = `{"Calendar::Event":[{"id":5190,"parent_id":4821,"occurrence_id":"4821_2026-10-08","type":"Calendar::Event","title":"Morning run with Priya","starts_at":"2026-10-08T11:00:00Z","ends_at":"2026-10-08T12:00:00Z","attendances":[{"id":2,"email_address":"priya@example.com","status":"accepted"}]}]}`
)

func TestRestrictedEventDelete(t *testing.T) {
	occurrence := []string{"--occurrence", "4821_2026-10-08"}
	for _, tt := range []struct {
		name         string
		work, family string
		args         []string
		allowed      bool
	}{
		{name: "a one-off event without guests", work: dentist, family: `{}`, allowed: true},
		{name: "a one-off event with guests", work: designReview, family: `{}`},
		// The event is on the second calendar: every calendar is read, not just the first.
		{name: "an event with guests on a later calendar", work: `{}`, family: designReview},
		{name: "an event it cannot find", work: `{}`, family: `{}`},
		{name: "a whole repeating series", work: weeklyRun, family: `{}`},
		{name: "one day of a series", work: weeklyRun, family: `{}`, args: append(occurrence, "--apply-to", "current"), allowed: true},
		// The series is guest-free, but that day was written out on another calendar with a
		// guest of its own.
		{name: "one day of a series that has guests of its own", work: weeklyRun, family: runWithGuests, args: append(occurrence, "--apply-to", "current")},
		{name: "every day from one on", work: weeklyRun, family: `{}`, args: append(occurrence, "--apply-to", "future")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var deleted atomic.Int32
			handler := calendarServer(t, tt.work, tt.family, &deleted)
			_, err := runRestricted(t, handler, append([]string{"event", "delete", "4821"}, tt.args...)...)
			if tt.allowed {
				if err != nil || deleted.Load() != 1 {
					t.Fatalf("err = %v, deletes = %d; want the event deleted", err, deleted.Load())
				}
				return
			}
			requireForbidden(t, err)
			if deleted.Load() != 0 {
				t.Errorf("deleted an event it should have refused")
			}
		})
	}
}

func TestSplitCommandLine(t *testing.T) {
	for _, tt := range []struct {
		line string
		want []string
	}{
		{"box list", []string{"box", "list"}},
		{"  box   view  imbox ", []string{"box", "view", "imbox"}},
		{`compose --subject 'Lunch on Friday?' -m "It's \"on\" me"`, []string{"compose", "--subject", "Lunch on Friday?", "-m", `It's "on" me`}},
		{`reply 1 -m 'it'\''s fine'`, []string{"reply", "1", "-m", "it's fine"}},
		{`search 'a; rm -rf /' $HOME` + "`id`", []string{"search", "a; rm -rf /", "$HOME`id`"}},
		{`search ''`, []string{"search", ""}},
		{"search caf\\é", []string{"search", "café"}},
		{"compose -m 'two\nlines'", []string{"compose", "-m", "two\nlines"}},
	} {
		got, err := splitCommandLine(tt.line)
		if err != nil {
			t.Errorf("splitCommandLine(%q): %v", tt.line, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitCommandLine(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
	for _, bad := range []string{`box 'list`, `box "list`, `box list\`} {
		if _, err := splitCommandLine(bad); err == nil {
			t.Errorf("splitCommandLine(%q) should fail", bad)
		}
	}
}
