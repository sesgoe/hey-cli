package cmd

// draftSavedHook, when set, is told the id of every draft a command saves before the
// command reports it. The restricted build uses it to remember which drafts are its own.
var draftSavedHook func(draftID int64) error
