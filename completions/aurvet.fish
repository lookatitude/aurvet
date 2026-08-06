# fish completion for aurvet
#
# The subcommand entries below are asserted against cmd/aurvet's dispatch switch
# by completions/completions_test.go. A new subcommand that is not added here
# fails that test by name.

complete -c aurvet -f

# Installed package names for -pkg, read from the local database directory. No
# network and no `pacman` execution: a completion reads, like the rest of the
# tool (INV-2).
function __fish_aurvet_packages
	for d in /var/lib/pacman/local/*/
		string replace -r -- '^(.*)-[^-]+-[^-]+$' '$1' (basename $d)
	end
end

# subcommands
complete -c aurvet -n __fish_use_subcommand -a scan -d 'sweep the system and report provenance findings'
complete -c aurvet -n __fish_use_subcommand -a diff -d 'classify drift against the signed baseline (= baseline diff)'
complete -c aurvet -n __fish_use_subcommand -a baseline -d 'the signed baseline and its trust chain'
complete -c aurvet -n __fish_use_subcommand -a triage -d 'ack, snooze or note a finding -- local, unsigned, expiring'
complete -c aurvet -n __fish_use_subcommand -a adjudicate -d 'record, list or revoke a signed judgement about a finding'
complete -c aurvet -n __fish_use_subcommand -a bundle -d 'emit a redacted fixture root reproducing one finding'
complete -c aurvet -n __fish_use_subcommand -a update -d 'fetch and verify the indicator bundle (never automatic)'
complete -c aurvet -n __fish_use_subcommand -a review -d 'analyse one recipe; never builds it'
complete -c aurvet -n __fish_use_subcommand -a install -d 'review the dependency closure, prompt, snapshot, hand over'
complete -c aurvet -n __fish_use_subcommand -a snapshot -d 'capture provenance for one pkgbase'
complete -c aurvet -n __fish_use_subcommand -a explain -d 'explain one finding by fingerprint'
complete -c aurvet -n __fish_use_subcommand -a doctor -d 'print the resolved configuration and its sources'
complete -c aurvet -n __fish_use_subcommand -a version -d 'print build identity'

# AURVET_FLAGS_BEGIN
# flags
complete -c aurvet -l json -o json -d 'emit machine-readable JSON instead of text'
complete -c aurvet -l no-network -o no-network -d 'skip every outbound request; network checks become coverage gaps'
complete -c aurvet -l since-last -o since-last -d 'scan: show only findings new since the previous scan'
complete -c aurvet -l show-recipe -o show-recipe -d 'review/install: print the recipe text in full'
complete -c aurvet -l offline-root -o offline-root -r -F -d 'examine a mounted filesystem instead of the running system'
complete -c aurvet -l min-severity -o min-severity -x -a 'info suspicious critical' -d 'reporting floor'
complete -c aurvet -l tier -o tier -x -a 'meta triage full paranoid' -d 'verification tier: how much of each file is examined'
complete -c aurvet -l allow-degraded -o allow-degraded -d 'scan: proceed unprivileged; the report is stamped DEGRADED and cannot exit 0'
complete -c aurvet -l pkg -o pkg -x -a '(__fish_aurvet_packages)' -d 'scan: analyse only this package (repeatable)'

complete -c aurvet -l key -o key -r -F -d 'baseline: an OpenSSH ed25519 private key file to sign with'
complete -c aurvet -l signer -o signer -x -d 'baseline: fingerprint of an ssh-agent key to sign with'
complete -c aurvet -l remote -o remote -x -d 'baseline pushed: the remote the chain was pushed to'
complete -c aurvet -l protected-remote -o protected-remote -d 'baseline pushed: assert the remote denies force-push'

complete -c aurvet -l reason -o reason -x -d 'adjudicate: why this finding is acceptable -- mandatory and recorded'
complete -c aurvet -l scope -o scope -x -a 'pin subject rule' -d 'adjudicate: blast radius of the judgement'
complete -c aurvet -l expiry-days -o expiry-days -x -d 'adjudicate: days the judgement lasts (default 180, max 365)'
complete -c aurvet -l force-rule-scope -o force-rule-scope -d 'adjudicate: the explicit force -scope rule requires'
complete -c aurvet -l bundle-url -o bundle-url -x -d 'update: the indicator bundle origin to fetch from'
complete -c aurvet -l check -o check -d 'update: report what an update would do; writes no cache and no floor'
complete -c aurvet -l version -o version -d 'print build identity, root fingerprints, delegation expiry, cached bundle version'
# AURVET_FLAGS_END

# baseline subcommands
complete -c aurvet -n '__fish_seen_subcommand_from baseline' -a 'init append status show verify pushed diff'

# adjudicate subcommands; the third form takes a finding fingerprint, which
# nothing local can enumerate without running a scan
complete -c aurvet -n '__fish_seen_subcommand_from adjudicate' -a 'list revoke'

# triage verbs: §12's middle weight, plus list and drop
complete -c aurvet -n '__fish_seen_subcommand_from triage' -a 'ack snooze note list drop'

# bundle takes a fingerprint and then a destination directory
complete -c aurvet -n '__fish_seen_subcommand_from bundle' -F

# review takes a directory or a pkgbase; only the directory is completable
complete -c aurvet -n '__fish_seen_subcommand_from review' -F
