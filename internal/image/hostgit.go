package image

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// HostGitConf are the -c settings of every git command Box runs in a host checkout: no fsmonitor (a hook program or a
// daemon), no pager, no external diff and no untracked cache (an index write). Command-line settings beat every
// config file, the checkout's own .git/config and whatever it includes among them.
var HostGitConf = []string{"core.fsmonitor=false", "core.pager=cat", "diff.external=", "core.untrackedCache=false"}

// HostGitEnv is the env of a git command in a host checkout: the caller's without any GIT_* variable (GIT_DIR,
// GIT_EXTERNAL_DIFF, GIT_CONFIG_*, …) or PAGER, never prompting, paging or taking optional locks.
func HostGitEnv() []string {
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") && !strings.HasPrefix(kv, "PAGER=") {
			env = append(env, kv)
		}
	}
	return append(env, "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C", "GIT_PAGER=cat", "PAGER=cat")
}

// GitConfigValues reads every value of a config key as git resolves it in dir, with no program run (reading config
// runs none): `git config [scope] -z --get-all key` with HostGitConf and HostGitEnv, so the system, global and (when
// git trusts dir) the repository's own config are read; scope ("--system", "--global") narrows it. pathType asks git
// to expand the value as a path (--type=path). nil when unset or on any failure. This read is the only way the host's
// system and global config reach the contained git commands: what they need is passed back with -c.
func GitConfigValues(ctx context.Context, gitBin, dir, scope, key string, pathType bool) []string {
	a := []string{"--no-pager"}
	for _, c := range HostGitConf {
		a = append(a, "-c", c)
	}
	a = append(a, "config")
	if scope != "" {
		a = append(a, scope)
	}
	if pathType {
		a = append(a, "--type=path")
	}
	cmd := exec.CommandContext(ctx, gitBin, append(a, "-z", "--get-all", key)...)
	cmd.Dir = dir
	cmd.Env = HostGitEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	vals := strings.Split(string(out), "\x00")
	return vals[:len(vals)-1] // each value ends with a NUL
}

// HostExcludesFile is core.excludesFile as git resolves it in dir from every config file (system, global, the
// checkout's own): "" when unset. The workspace build and apply both read it this way, so a file ignored through any of
// them is ignored by both.
func HostExcludesFile(ctx context.Context, gitBin, dir string) string {
	vals := GitConfigValues(ctx, gitBin, dir, "", "core.excludesFile", true)
	if len(vals) == 0 {
		return ""
	}
	return vals[len(vals)-1]
}
