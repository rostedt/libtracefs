# sqlhist completion

# use the library tracefs_sql() completion

thisdir=`dirname $BASH_SOURCE`
if [ -e $thisdir/tracefs_sql.bash ]; then
. $thisdir/tracefs_sql.bash
elif [ -e $thisdir/../src/tracefs_sql.bash ]; then
. $thisdir/../src/tracefs_sql.bash
else
tracefs_sql_completion()
{
    return
}
fi

found_select()
{
    local words=("$@")
    local i=$COMP_CWORD

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=$(echo ${words[$i]} | tr A-Z a-z)
	if [ $w == "select" ]; then
	    return 0
	fi
    done
    return 1
}

_sqlhist_complete()
{
    local cur=""
    local prev=""
    local words=()

    # Not to use COMP_WORDS to avoid buggy behavior of Bash when
    # handling with words including ":", like:
    #
    # prev="${COMP_WORDS[COMP_CWORD-1]}"
    # cur="${COMP_WORDS[COMP_CWORD]}"
    #
    # Instead, we use _get_comp_words_by_ref() magic.
    _get_comp_words_by_ref -n : cur prev words

    if `found_select ${words[@]}` ; then
	tracefs_sql_completion "$prev" "$cur" ${words[@]}
	return
    fi
    local cmds=$(sqlhist -h 2>&1 | \
                     grep '^ *-' | sed -e 's/^ *\(-[^ ]*\).*/\1/')
    COMPREPLY=( $(compgen -W "${cmds} SELECT" -- "${cur}") )
    if [ ${#COMPREPLY[@]} -eq 0 ]; then
	local w="select"
	if [ "$w" != "${w##$cur}" ]; then
	    COMPREPLY=("$w")
	fi
    fi
}
complete -F _sqlhist_complete sqlhist
