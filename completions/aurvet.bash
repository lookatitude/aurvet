# bash completion for aurvet
#
# The subcommand list below is asserted against cmd/aurvet's dispatch switch by
# completions/completions_test.go. A new subcommand that is not added here fails
# that test by name -- completions rot silently otherwise, because a missing
# completion is indistinguishable from "no match".

# AURVET_COMMANDS_BEGIN
_aurvet_commands=(scan diff baseline triage adjudicate bundle update review install snapshot explain doctor version)
# AURVET_COMMANDS_END

# AURVET_FLAGS_BEGIN
_aurvet_flags=(
	-json
	-key
	-protected-remote
	-remote
	-signer
	-min-severity
	-no-network
	-offline-root
	-show-recipe
	-since-last
	-tier
	-reason
	-scope
	-expiry-days
	-force-rule-scope
	-bundle-url
	-check
	-allow-degraded
	-pkg
	-version
)
# AURVET_FLAGS_END

_aurvet() {
	local cur prev i cmd=""
	cur=${COMP_WORDS[COMP_CWORD]}
	prev=${COMP_WORDS[COMP_CWORD - 1]}

	# Flags may appear on either side of the subcommand, so find the
	# subcommand by scanning rather than by position.
	for ((i = 1; i < COMP_CWORD; i++)); do
		local w=${COMP_WORDS[i]}
		case $w in
		-*) continue ;;
		esac
		# Skip the value of a flag that takes one.
		case ${COMP_WORDS[i - 1]} in
		-min-severity | --min-severity | -offline-root | --offline-root) continue ;;
		-tier | --tier | -key | --key | -signer | --signer | -remote | --remote) continue ;;
		-reason | --reason | -scope | --scope | -expiry-days | --expiry-days) continue ;;
		-bundle-url | --bundle-url | -pkg | --pkg) continue ;;
		esac
		local c
		for c in "${_aurvet_commands[@]}"; do
			if [[ $w == "$c" ]]; then
				cmd=$c
				break
			fi
		done
		[[ -n $cmd ]] && break
	done

	case $prev in
	-min-severity | --min-severity)
		mapfile -t COMPREPLY < <(compgen -W "info suspicious critical" -- "$cur")
		return
		;;
	-tier | --tier)
		# Values only; the tier a run REPORTS is derived from the work it did,
		# so there is nothing here that asserts coverage.
		mapfile -t COMPREPLY < <(compgen -W "meta triage full paranoid" -- "$cur")
		return
		;;
	-scope | --scope)
		# pin is the narrowest and the default. rule turns a check off
		# everywhere and additionally needs -force-rule-scope.
		mapfile -t COMPREPLY < <(compgen -W "pin subject rule" -- "$cur")
		return
		;;
	-reason | --reason | -expiry-days | --expiry-days | -bundle-url | --bundle-url)
		# Free text, a number and a URL. Nothing to offer, and a completion must
		# not invent a reason for an operator.
		COMPREPLY=()
		return
		;;
	-offline-root | --offline-root)
		mapfile -t COMPREPLY < <(compgen -d -- "$cur")
		return
		;;
	-pkg | --pkg)
		# Installed package names, from the local database's directory listing.
		# No network, and no `pacman` execution: a completion reads, like the rest
		# of this tool (INV-2).
		local d n
		COMPREPLY=()
		for d in /var/lib/pacman/local/*/; do
			[[ -d $d ]] || continue
			n=${d%/}
			n=${n##*/}
			n=${n%-*}
			n=${n%-*}
			[[ $n == "$cur"* ]] && COMPREPLY+=("$n")
		done
		return
		;;
	-key | --key)
		mapfile -t COMPREPLY < <(compgen -f -- "$cur")
		return
		;;
	esac

	if [[ $cur == -* ]]; then
		mapfile -t COMPREPLY < <(compgen -W "${_aurvet_flags[*]}" -- "$cur")
		return
	fi

	case $cmd in
	"")
		mapfile -t COMPREPLY < <(compgen -W "${_aurvet_commands[*]}" -- "$cur")
		;;
	review)
		# A recipe directory or a pkgbase; only the directory is completable.
		mapfile -t COMPREPLY < <(compgen -d -- "$cur")
		;;
	baseline)
		mapfile -t COMPREPLY < <(compgen -W "init append status show verify pushed diff" -- "$cur")
		;;
	adjudicate)
		# list and revoke, plus a finding fingerprint nothing local can enumerate.
		mapfile -t COMPREPLY < <(compgen -W "list revoke" -- "$cur")
		;;
	triage)
		# the three weights plus list and drop; the fingerprint that follows comes
		# from the report and nothing local can enumerate it.
		mapfile -t COMPREPLY < <(compgen -W "ack snooze note list drop" -- "$cur")
		;;
	bundle)
		# a finding fingerprint, then an output directory.
		mapfile -t COMPREPLY < <(compgen -d -- "$cur")
		;;
	update)
		# takes no arguments: an update is the whole command. --check is a flag and
		# is offered by the flag branch above.
		COMPREPLY=()
		;;
	diff)
		# `aurvet diff` is `aurvet baseline diff` and takes no argument either.
		COMPREPLY=()
		;;
	*)
		# install/snapshot/explain take a pkgbase or a fingerprint. aurvet does
		# not query the AUR from a completion function: a completion must not
		# make a network request the user did not ask for.
		COMPREPLY=()
		;;
	esac
}

complete -F _aurvet aurvet
