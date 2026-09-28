//go:build unix

package cmd

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/basecamp/hey-sdk/go/pkg/generated"
	"github.com/basecamp/hey-sdk/go/pkg/hey"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/basecamp/hey-cli/internal/apierr"
	attachmentfiles "github.com/basecamp/hey-cli/internal/attachments"
	"github.com/basecamp/hey-cli/internal/config"
	"github.com/basecamp/hey-cli/internal/htmlutil"
	"github.com/basecamp/hey-cli/internal/output"
)

// The restricted build (cmd/hey-gordy) is the HEY CLI an agent reaches over SSH. It
// holds the account's credentials on a host the agent cannot log in to, and is the
// only thing standing between the agent and a token that can do anything the
// account can: HEY has no scopes, and saving a draft and sending one are the same
// endpoints. So the binary enforces the policy itself:
//
//   - The command tree is pruned to restricted.surface, an allowlist in .surface's
//     format. Whatever upstream adds stays out until it is listed.
//   - A flag not on the allowlist is refused, not merely hidden.
//   - compose and reply always save a draft.
//   - A draft may be edited or deleted only if this build saved it, and never once
//     it has a scheduled delivery, which would send it.
//   - An event with guests is never edited or deleted: HEY emails guests about it.
//   - Only restrictedBaseURL is ever sent the token.

//go:embed restricted.surface
var restrictedSurfaceFile string

// restrictedBaseURL is the one server the restricted build talks to. Tests point it
// at their own server.
var restrictedBaseURL = "https://app.hey.com"

// restrictedExtras are commands the restricted build keeps that .surface does not
// list: help is hidden, so .surface skips it.
var restrictedExtras = []string{"hey help"}

func restrictedSurface() map[string]bool {
	allowed := map[string]bool{}
	for _, line := range strings.Split(restrictedSurfaceFile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allowed[line] = true
	}
	for _, extra := range restrictedExtras {
		allowed[extra] = true
	}
	return allowed
}

// ExecuteRestricted runs the restricted build. Under an SSH forced command the
// arguments come from SSH_ORIGINAL_COMMAND, split here without a shell; otherwise
// from the command line.
func ExecuteRestricted() {
	args := os.Args[1:]
	if original, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND"); ok {
		split, err := splitCommandLine(original)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(output.ExitCodeFor(apierr.ErrUsage(err.Error())))
		}
		if len(split) > 0 && split[0] == "hey" {
			split = split[1:]
		}
		args = split
	}

	if err := restrictEnvironment(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	logInvocation(args)

	root := newRestrictedRootCmd()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		err = normalizeCobraError(err)
		if writer == nil {
			format := output.FormatFromFlags(jsonFlag, quietFlag, idsOnly, countFlag, markdownF, styledFlag, agentFlag)
			writer = output.New(output.Options{Format: format})
		}
		writer.Err(err)
		os.Exit(output.ExitCodeFor(err))
	}
}

// restrictEnvironment leaves nothing in the environment that could redirect the
// build: no HEY_* override (a token, a base URL, a cable URL), no editor to launch,
// and no working directory with a repository-local .hey/config.json above it.
func restrictEnvironment() error {
	for _, entry := range os.Environ() {
		if name, _, _ := strings.Cut(entry, "="); strings.HasPrefix(name, "HEY_") {
			if err := os.Unsetenv(name); err != nil {
				return err
			}
		}
	}
	for name, value := range map[string]string{
		"HEY_NONINTERACTIVE": "1",
		"HEY_NO_KEYRING":     "1",
		"EDITOR":             "/bin/false",
		"VISUAL":             "/bin/false",
	} {
		if err := os.Setenv(name, value); err != nil {
			return err
		}
	}
	return os.Chdir("/")
}

// logInvocation records each call in the system log, so the host keeps an audit
// trail of what the agent asked for. Long arguments — message bodies — are cut short.
func logInvocation(args []string) {
	logger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_AUTH, "hey-gordy")
	if err != nil {
		return
	}
	defer func() { _ = logger.Close() }()
	quoted := make([]string, len(args))
	for i, arg := range args {
		if len(arg) > 120 {
			arg = arg[:120] + "…"
		}
		quoted[i] = strconv.Quote(arg)
	}
	_ = logger.Info("argv=[" + strings.Join(quoted, " ") + "]")
}

func newRestrictedRootCmd() *cobra.Command {
	root := newRootCmd()
	root.Short = "Read and organize HEY email and write drafts (restricted build)."
	root.CompletionOptions.DisableDefaultCmd = true
	if attachment, _, err := root.Find([]string{"attachment"}); err == nil && attachment != root {
		attachment.AddCommand(newAttachmentGetCommand())
	}

	allowed := restrictedSurface()
	pruneCommands(root, allowed)
	hideUnlistedFlags(root, allowed)
	describeRestrictedCommands(root)

	// The skill refresh writes agent files into the home directory; nothing here should.
	root.PersistentPostRunE = nil

	inner := root.PersistentPreRunE
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := refuseUnlistedFlags(cmd, allowed); err != nil {
			return err
		}
		if err := forceDraft(cmd); err != nil {
			return err
		}
		draftSavedHook = recordOwnedDraft
		if err := inner(cmd, args); err != nil {
			return err
		}
		if isHelpReference(cmd) || versionFlag {
			return nil
		}
		if cfg == nil || strings.TrimRight(cfg.BaseURL, "/") != restrictedBaseURL {
			return apierr.ErrForbidden("this build only talks to " + restrictedBaseURL)
		}
		return restrictedPolicy(cmd, args)
	}
	return root
}

// describeRestrictedCommands keeps help from promising what this build will not do:
// the curated root help names the TUI and sending, and compose and reply only draft.
func describeRestrictedCommands(root *cobra.Command) {
	for path, short := range map[string]string{
		"compose": "Write a new email as a draft",
		"reply":   "Write a reply to a thread as a draft",
	} {
		if cmd, _, err := root.Find([]string{path}); err == nil && cmd != root {
			cmd.Short = short
		}
	}
	help := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd != cmd.Root() || agentFlag {
			help(cmd, args)
			return
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%s\n\nUSAGE\n  hey <command> [flags]\n\nCOMMANDS\n", cmd.Short)
		for _, sub := range cmd.Commands() {
			if sub.IsAvailableCommand() {
				fmt.Fprintf(w, "  %-14s %s\n", sub.Name(), sub.Short)
			}
		}
		fmt.Fprintln(w, "\nRun 'hey <command> --help' for a command's flags and examples.")
	})
}

// pruneCommands removes every command the allowlist does not name.
func pruneCommands(parent *cobra.Command, allowed map[string]bool) {
	for _, sub := range append([]*cobra.Command(nil), parent.Commands()...) {
		if !allowed[sub.CommandPath()] {
			parent.RemoveCommand(sub)
			continue
		}
		pruneCommands(sub, allowed)
	}
}

// flagOwner is the command that defines f for cmd: cmd itself, or the ancestor whose
// persistent flag it inherits.
func flagOwner(cmd *cobra.Command, f *pflag.Flag) *cobra.Command {
	for c := cmd; c != nil; c = c.Parent() {
		if c.LocalFlags().Lookup(f.Name) == f {
			return c
		}
	}
	return cmd
}

func flagAllowed(cmd *cobra.Command, f *pflag.Flag, allowed map[string]bool) bool {
	if f.Name == "help" {
		return true
	}
	return allowed[flagOwner(cmd, f).CommandPath()+" --"+f.Name]
}

func hideUnlistedFlags(cmd *cobra.Command, allowed map[string]bool) {
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if !flagAllowed(cmd, f, allowed) {
			f.Hidden = true
		}
	})
	for _, sub := range cmd.Commands() {
		hideUnlistedFlags(sub, allowed)
	}
}

func refuseUnlistedFlags(cmd *cobra.Command, allowed map[string]bool) error {
	var refused []string
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if !flagAllowed(cmd, f, allowed) {
			refused = append(refused, "--"+f.Name)
		}
	})
	if len(refused) == 0 {
		return nil
	}
	sort.Strings(refused)
	return apierr.ErrForbidden(fmt.Sprintf("%s is not available in this build", strings.Join(refused, ", ")))
}

// forceDraft makes compose and reply save a draft whatever they were asked.
func forceDraft(cmd *cobra.Command) error {
	switch cmd.CommandPath() {
	case "hey compose", "hey reply":
		return cmd.Flags().Set("draft", "true")
	}
	return nil
}

func restrictedPolicy(cmd *cobra.Command, args []string) error {
	switch cmd.CommandPath() {
	case "hey draft edit", "hey draft delete":
		return refuseDraftsNotOurs(cmd, args)
	case "hey event edit", "hey event delete":
		return refuseEventWithGuests(cmd, args)
	}
	return nil
}

// Drafts

func ownedDraftsPath() string {
	return filepath.Join(config.StateDir(), "restricted-drafts.json")
}

// withOwnedDrafts runs fn on the set of draft ids this build has saved, under a file
// lock so concurrent invocations do not drop each other's ids. fn reports whether it
// changed the set.
func withOwnedDrafts(fn func(ids map[int64]bool) bool) error {
	path := ownedDraftsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- fixed path under hey's own state dir
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // G115: fd fits in int
		return err
	}

	ids := map[int64]bool{}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed path under hey's own state dir
	switch {
	case err == nil:
		var list []int64
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		for _, id := range list {
			ids[id] = true
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}

	if !fn(ids) {
		return nil
	}
	list := make([]int64, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	data, err = json.Marshal(list)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func recordOwnedDraft(id int64) error {
	return withOwnedDrafts(func(ids map[int64]bool) bool {
		ids[id] = true
		return true
	})
}

// refuseDraftsNotOurs lets draft edit and delete touch only drafts this build saved,
// and none with a scheduled delivery: HEY sends a scheduled draft by itself, so
// changing one would change what goes out under the account's name.
func refuseDraftsNotOurs(cmd *cobra.Command, args []string) error {
	ids := make([]int64, 0, len(args))
	for _, arg := range args {
		id, err := parsePositiveID(arg, "draft")
		if err != nil {
			return err
		}
		ids = append(ids, id)
	}

	var foreign []string
	if err := withOwnedDrafts(func(owned map[int64]bool) bool {
		for _, id := range ids {
			if !owned[id] {
				foreign = append(foreign, strconv.FormatInt(id, 10))
			}
		}
		return false
	}); err != nil {
		return err
	}
	if len(foreign) > 0 {
		refusal := apierr.ErrForbidden(fmt.Sprintf("draft %s was not written by this agent", strings.Join(foreign, ", ")))
		refusal.Hint = "only drafts saved through this build can be edited or deleted; write a new draft instead"
		return refusal
	}

	for _, id := range ids {
		edit, err := sdk.Messages().GetEdit(cmd.Context(), id)
		if err != nil {
			return apierr.FromSDK(err)
		}
		if edit != nil && !edit.ScheduledDeliveryAt.IsZero() {
			refusal := apierr.ErrForbidden(fmt.Sprintf("draft %d is scheduled to be sent", id))
			refusal.Hint = "a scheduled draft has been approved to send, so it is left alone"
			return refusal
		}
	}
	return nil
}

// Events

// refuseEventWithGuests keeps edits and deletes to events nobody else is on. HEY emails
// an event's guests about it, so changing one speaks for the account.
//
// Only a write whose every affected day can be read is allowed: a one-off event, read
// over every calendar, or one day of a repeating event (--apply-to current), read on that
// day over every calendar, series and written-out day both. A write to a whole series or
// to every day from one on is refused: any day of a series can have been given guests of
// its own, on any date, and no bounded read proves otherwise. So is an event that cannot
// be found, since its guests are unknown.
func refuseEventWithGuests(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil // the command's own argument check answers this
	}
	id, err := parsePositiveID(args[0], "event")
	if err != nil {
		return err
	}
	ctx := cmd.Context()

	occurrenceValue, _ := cmd.Flags().GetString("occurrence")
	applyTo, _ := cmd.Flags().GetString("apply-to")
	write, err := parseOccurrenceFlags(cmd, id, occurrenceValue, applyTo)
	if err != nil {
		return err
	}

	if write != nil {
		if write.scope != hey.OccurrenceScopeThisEvent {
			return errWholeSeries(id)
		}
		window, err := occurrenceDayWindow(ctx, write.occurrence.Date)
		if err != nil {
			return err
		}
		rows, err := readEventRows(ctx, window)
		if err != nil {
			return err
		}
		seriesFound := false
		for _, row := range rows {
			if row.Id != id && row.ParentId != id && row.OccurrenceId != write.occurrence.String() {
				continue
			}
			seriesFound = seriesFound || row.Id == id
			if len(attendeeAddresses(row.Attendances)) > 0 {
				return errEventHasGuests(id)
			}
		}
		if !seriesFound {
			return errEventUnreadable(id)
		}
		return nil
	}

	on := ""
	if cmd.CommandPath() == "hey event edit" && len(args) > 1 {
		on = args[1]
	}
	window, err := eventSearchWindow(ctx, on)
	if err != nil {
		return err
	}
	rows, err := readEventRows(ctx, window)
	if err != nil {
		return err
	}
	found := false
	for _, row := range rows {
		if row.Id != id && row.ParentId != id {
			continue
		}
		found = true
		if row.Recurring || row.ParentId == id {
			return errWholeSeries(id)
		}
		if len(attendeeAddresses(row.Attendances)) > 0 {
			return errEventHasGuests(id)
		}
	}
	if !found {
		return errEventUnreadable(id)
	}
	return nil
}

// readEventRows reads every calendar in the window, never stopping at the first that holds
// the event: a day of a series can have been moved to another calendar with guests of its own.
func readEventRows(ctx context.Context, window recordingWindow) ([]generated.Recording, error) {
	var rows []generated.Recording
	for _, calendarID := range window.calendars {
		events, err := window.readCalendar(ctx, calendarID, []string{recordingTypeEvent})
		if err != nil {
			return nil, err
		}
		rows = append(rows, events...)
	}
	return rows, nil
}

func errEventHasGuests(id int64) error {
	refusal := apierr.ErrForbidden(fmt.Sprintf("event %d has guests", id))
	refusal.Hint = "HEY emails an event's guests when it changes, so events with guests are left alone"
	return refusal
}

func errWholeSeries(id int64) error {
	refusal := apierr.ErrForbidden(fmt.Sprintf("event %d repeats, and a change to the whole series or to every day from one on cannot be checked for guests", id))
	refusal.Hint = fmt.Sprintf("change one day at a time: hey event day <YYYY-MM-DD> lists occurrence ids, then --occurrence %d_<YYYY-MM-DD> --apply-to current", id)
	return refusal
}

func errEventUnreadable(id int64) error {
	refusal := apierr.ErrForbidden(fmt.Sprintf("event %d could not be read to check it has no guests", id))
	refusal.Hint = fmt.Sprintf("hey event edit %d <YYYY-MM-DD> reads the day it starts on", id)
	return refusal
}

// Attachments

// newAttachmentGetCommand writes an attachment's bytes to stdout. The restricted build
// has no attachment save: over SSH the bytes belong on the caller's side, and nothing
// here should write files where the credentials live.
func newAttachmentGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get <attachment-id>",
		Short: "Write an attachment to stdout",
		Annotations: map[string]string{
			"agent_notes": "Streams the raw bytes of the attachment identified by an ID from `hey attachment list <thread-id>` to stdout; redirect it to a file.",
		},
		Example: `  hey attachment get 67890:1 > quarterly-report.pdf`,
		Args:    usageExactOneArg(),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			messageID, selector, err := parseAttachmentID(args[0])
			if err != nil {
				return err
			}
			message, err := sdk.Messages().Get(cmd.Context(), messageID)
			if err != nil {
				return apierr.FromSDK(err)
			}
			if message == nil {
				return apierr.ErrNotFound("message", strconv.FormatInt(messageID, 10))
			}
			attachment, found := findAttachmentByID(messageID, fmt.Sprintf("%d:%s", messageID, selector),
				htmlutil.ExtractAttachments(message.Content))
			if !found {
				return apierr.ErrNotFound("attachment", args[0])
			}
			if !attachmentfiles.IsHEYBlobURL(attachment.URL) {
				return apierr.ErrAPI(0, "attachment URL does not identify a HEY blob")
			}
			if _, _, err := sdk.DownloadBlob(cmd.Context(), attachment.URL, cmd.OutOrStdout()); err != nil {
				return apierr.FromSDK(err)
			}
			return nil
		},
	}
}

// Command line

// splitCommandLine splits an SSH command line into arguments the way a POSIX shell
// splits words, with none of a shell's expansion: single quotes are literal, double
// quotes honor \\ \" \$ \` and a backslash escapes the next character. Nothing is
// ever run through a shell, so ; | & $ and the rest are ordinary characters.
func splitCommandLine(line string) ([]string, error) {
	var (
		args   []string
		word   strings.Builder
		inWord bool
	)
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == '\'':
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("unterminated single quote in command")
			}
			word.WriteString(line[i+1 : i+1+end])
			inWord = true
			i += end + 2
		case c == '"':
			i++
			closed := false
			for i < len(line) {
				d := line[i]
				if d == '"' {
					closed = true
					i++
					break
				}
				if d == '\\' && i+1 < len(line) && strings.IndexByte("\\\"$`\n", line[i+1]) >= 0 {
					if line[i+1] != '\n' {
						word.WriteByte(line[i+1])
					}
					i += 2
					continue
				}
				word.WriteByte(d)
				i++
			}
			if !closed {
				return nil, errors.New("unterminated double quote in command")
			}
			inWord = true
		case c == '\\':
			if i+1 >= len(line) {
				return nil, errors.New("trailing backslash in command")
			}
			_, size := utf8.DecodeRuneInString(line[i+1:])
			if line[i+1] != '\n' {
				word.WriteString(line[i+1 : i+1+size])
			}
			inWord = true
			i += 1 + size
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				args = append(args, word.String())
				word.Reset()
				inWord = false
			}
			i++
		default:
			word.WriteByte(c)
			inWord = true
			i++
		}
	}
	if inWord {
		args = append(args, word.String())
	}
	return args, nil
}
