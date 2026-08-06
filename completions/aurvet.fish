# fish completion for aurvet
#
# The subcommand entries below are asserted against cmd/aurvet's dispatch switch
# by completions/completions_test.go. A new subcommand that is not added here
# fails that test by name.

complete -c aurvet -f

# subcommands
complete -c aurvet -n __fish_use_subcommand -a scan -d 'sweep the system and report provenance findings'
complete -c aurvet -n __fish_use_subcommand -a baseline -d 'the signed baseline and its trust chain'
complete -c aurvet -n __fish_use_subcommand -a review -d 'analyse one recipe; never builds it'
complete -c aurvet -n __fish_use_subcommand -a install -d 'review the dependency closure, prompt, snapshot, hand over'
complete -c aurvet -n __fish_use_subcommand -a snapshot -d 'capture provenance for one pkgbase'
complete -c aurvet -n __fish_use_subcommand -a explain -d 'explain one finding by fingerprint'
complete -c aurvet -n __fish_use_subcommand -a doctor -d 'print the resolved configuration and its sources'
complete -c aurvet -n __fish_use_subcommand -a version -d 'print build identity'

# flags
complete -c aurvet -l json -o json -d 'emit machine-readable JSON instead of text'
complete -c aurvet -l no-network -o no-network -d 'skip every outbound request; network checks become coverage gaps'
complete -c aurvet -l since-last -o since-last -d 'scan: show only findings new since the previous scan'
complete -c aurvet -l show-recipe -o show-recipe -d 'review/install: print the recipe text in full'
complete -c aurvet -l offline-root -o offline-root -r -F -d 'examine a mounted filesystem instead of the running system'
complete -c aurvet -l min-severity -o min-severity -x -a 'info suspicious critical' -d 'reporting floor'

complete -c aurvet -l key -o key -r -F -d 'baseline: an OpenSSH ed25519 private key file to sign with'
complete -c aurvet -l signer -o signer -x -d 'baseline: fingerprint of an ssh-agent key to sign with'
complete -c aurvet -l remote -o remote -x -d 'baseline pushed: the remote the chain was pushed to'
complete -c aurvet -l protected-remote -o protected-remote -d 'baseline pushed: assert the remote denies force-push'

# baseline subcommands
complete -c aurvet -n '__fish_seen_subcommand_from baseline' -a 'init append status verify pushed diff'

# review takes a directory or a pkgbase; only the directory is completable
complete -c aurvet -n '__fish_seen_subcommand_from review' -F
