make_small() {
    local w=$1

    echo $w | tr A-Z a-z
}

prev_keyword() {
    local i=$1
    shift
    local words=("$@")

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=$(make_small ${words[$i]})

	case $w in
	    select)
		      echo "select"
		      return
		      ;;
		  from)
		      echo "from"
		      return
		      ;;
		  as)
		      echo "as"
		      return
		      ;;
		  on)
		      echo "on"
		      return
		      ;;
		  join)
		      echo "join"
		      return
		      ;;
		  where)
		      echo "where"
		      return
		      ;;
		  cast)
		      echo "cast"
		      return
		      ;;
		  *)
		      if [ "$w" != "${w%%,}" ]; then
			  echo ","
			  return
		      fi
		      if [ "$w" != "${w%%=}" ]; then
			  echo "="
			  return
		      fi
		      if [ "$w" != "${w%%&}" ]; then
			  echo "&"
			  return
		      fi
		      ;;
	    esac
	done
	    echo ""
}

prev_command() {
    local i=$1
    shift
    local words=("$@")

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=$(make_small ${words[$i]})

	case $w in
	    select)
		      echo "select"
		      return
		      ;;
		  from)
		      echo "from"
		      return
		      ;;
		  on)
		      echo "on"
		      return
		      ;;
		  join)
		      echo "join"
		      return
		      ;;
		  where)
		      echo "where"
		      return
		      ;;
		  cast)
		      echo "cast"
		      return
		      ;;
		  *)
		      # treat commas as a "select"
		      if [ "$w" != "${w%%,}" ]; then
			  echo "select"
			  return
		      fi
		      ;;
	    esac
	done
	    echo ""
}

add_vars() {
    local words=("$@")

    local i=$COMP_CWORD

    local event=""

    let found_from=0
    let found_as=0

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=$(make_small ${words[$i]})

	case $w in
	    "from")
		let found_from=1
		;;
	    "as")
		# Do not add the event itself if it was used by name
		if [ $found_as -eq 0 ]; then
		    event=${words[$i-1]};
		fi
		let found_as=1
		;;
	    *)
		if [ $found_from -eq 1 ]; then
		    start=$(echo $w | sed -e 's/\.[^\.]*$//')
		    if [ "$start" != "$w" -a "$start" == "${start%%\.*}" -a \
		         "$start" != "$event" ]; then
			echo -n "$start "
		    fi
		fi
		;;
	esac
    done
}

add_options() {
    local cur="$1"
    local list="$2"

    COMPREPLY=( $(compgen -W "${list}" -- "${cur}") )
}

print_fields() {
    local event=$1
    local var=$2
    local extra=$3

    local list=$(trace-cmd list -e "^${event/\./:}\$" -F |  cut -d';' -f1 | sed -ne 's/\t.*:.* \(.*\)/\1/p' |sed -e 's/\[.*\]//')

    for field in $list $extra; do
	if [ -z "$var" ]; then
	    echo "$event.$field"
	else
	    echo "$var.$field"
	fi
    done
}

__list_events() {
    local cur=$1

    local list=$(trace-cmd list -e "$cur")
    local prefix=${cur%%:*}
    if [ -z "$cur" -o  "$cur" != "$prefix" ]; then
	echo "${list}"
    else
	local events=$(for e in $list; do echo ${e/*:/}; done | sort -u)
	local systems=$(for s in $list; do echo ${s/:*/:}; done | sort -u)

	echo "${events} ${systems}"
    fi
}

select_options() {
    local cur=$1
    local extra=$2
    local select_list="$extra"
    local select_fields=" TIMESTAMP TIMESTAMP_USECS STACKTRACE COMM"
    local list;
    # Do not show events if nothing was typed yet
    if [ ! -z "$cur" ]; then
	list=$(__list_events "${cur/\./:}" | sed -e 's/:/./g')
	if [ "cast" != "${cast%%$cur}" ]; then
	    list+=" cast"
	fi
    fi
    add_options "$cur" "$list $select_list"
    local cnt=${#COMPREPLY[@]}
    if [ $cnt -eq 1 ]; then
	local comp=${COMPREPLY[0]}
	local w=$(compgen -W "$select_list" -- "$comp" )
	if [ -z "$w" -a $(make_small "$comp") != "cast" ]; then
	    COMPREPLY=("$comp.")
	    compopt -o nospace
	fi
    elif [ $cnt -eq 0 ]; then
	local w=$(echo $cur | sed -e 's/\.[^\.]*$//')
	list=$(print_fields $w "" "$select_fields")
	COMPREPLY=( $(compgen -W "${list}" -- "${cur}") )
    fi
}

check_as() {
    local words=("$@")

    last_key=$(prev_keyword $COMP_CWORD ${words[@]})
    if [ "$last_key" != "as" ]; then
	echo -n "AS"
    fi
}

on_list() {
    local type=$1
    shift
    local words=("$@")

    local i=$COMP_CWORD

    local var=""

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=$(make_small ${words[$i]})
	case $w in
	    "from"|"join")
		if [ $w == $type ]; then
		    print_fields ${words[$i+1]} "$var"
		    return
		fi
		var=""
		;;
	    as)
		var=${words[$i+1]}
		;;
	esac
    done
}

update_completion() {
    local cur=$1
    shift
    local words=("$@")

    if [ ${#COMPREPLY[@]} -gt 0 ]; then
	return
    fi

    for w in ${words[@]}; do
	if [ "$w" != "${w##$cur}" ]; then
	    COMPREPLY=("$w")
	    return
	fi
    done
}

# return 0 if it was handled, otherwise return 1
tracefs_sql_completion()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    if [ "$cur" != "${cur%%,}" ]; then
	COMPREPLY=("$cur")
	return 0
    fi

    local p=$(make_small $prev)

    if [ "$p" != "${p%%,}" ]; then
	p=$(prev_command $COMP_CWORD ${words[@]})
    fi

    case "$p" in
	"select")
	    select_options "$cur" "CAST TIMESTAMP_DELTA TIMESTAMP_DELTA_USECS"
	    ;;
	"on")
	    list=$(on_list "from" ${words[@]})
	    add_options "$cur" "$list"
	    ;;
	"where")
	    flist=$(on_list "from" ${words[@]})
	    jlist=$(on_list "join" ${words[@]})
	    add_options "$cur" "$flist $jlist"
	    ;;
	"cast")
	    COMPREPLY=("'('")
	    ;;
	"as")
	    local last_cmd=$(prev_command $COMP_CWORD ${words[@]})
	    case $last_cmd in
		"select")
		    if [ ! -z "$cur" ]; then
			COMPREPLY=("$cur" "$cur,")
		    fi
		    ;;
		"from"|"join")
		    list=$(add_vars ${words[@]})
		    if [ ! -z "$list" ]; then
			add_options "$cur" "$list"
		    fi
		    ;;
		"cast")
		    local list="hex sym sym-offset log log2 buckets stacktrace"
		    local w;
		    if [ -z "$cur" ]; then
			w=${words[$COMP_CWORD-1]}
		    else
			w=${words[$COMP_CWORD-2]}
		    fi
		    if [ "$w" != "${w%%.common_pid}" ]; then
			list+=" execname"
		    fi
		    add_options "$cur" "$list"
		    ;;
	    esac
	    ;;
	"from"|"join")
	    local list=$(trace-cmd list -e "${cur/\./:}" | tr : .)
	    local prefix=${cur/\./}
	    if [ -z "$cur" -o  "$cur" != "$prefix" ]; then
		COMPREPLY=( $(compgen -W "${list}" -- "${cur}") )
	    else
		local events=$(for e in $list; do echo ${e/*\./}; done | sort -u)
	        local systems=$(for s in $list; do echo ${s/\.*/.}; done | sort -u)

		COMPREPLY=( $(compgen -W "all ${events} ${systems}" -- "${cur}") )
	    fi
	    ;;
	# TIMESTAMP_DELTA must be labeled
	"timestamp_delta"|"timestamp_delta_usecs")
	    COMPREPLY=( $(compgen -W "AS" -- "${cur}") )
	    update_completion "$cur" "as"
	    ;;
	"'('")
	    if [ ! -z "$cur" ]; then
		select_options "$cur"
	    fi
	    ;;
	"')'")
	    add_options "$cur" "FROM , $list"
	    update_completion "$cur" from $alist
	    ;;
	*)
	    local last_cmd=$(prev_command $COMP_CWORD ${words[@]})
	    local list=$(check_as ${words[@]})
	    local alist=""
	    if [ ! -z "$list" ]; then
		alist="as"
	    fi
	    case $last_cmd in
		"select")
		    if [ "$cur" != "${cur%%,}" ]; then
			select_options "$cur" "CAST TIMESTAMP_DELTA TIMESTAMP_DELTA_USECS  $list"
		    else
			add_options "$cur" "FROM , $list"
			update_completion "$cur" from $alist
		    fi
		    ;;
		"from")
		    add_options "$cur" "JOIN $list"
		    update_completion "$cur" join $alist
		    ;;
		"join")
		    add_options "$cur" "ON $list"
		    update_completion "$cur" on $alist
		    ;;
		"on")
		    if [ "$cur" != "${cur%%=}" ]; then
			COMPREPLY=("")
		    else
			last_key=$(prev_keyword $COMP_CWORD ${words[@]})
			if [ "$last_key" == "=" ]; then
			    if [ $prev == "=" ]; then
				list=$(on_list "join" ${words[@]})
				add_options "$cur" "$list"
			    else
				add_options "$cur" "WHERE"
				update_completion "$cur" where
			    fi
			else
			    add_options "$cur" "="
			fi
		    fi
		    ;;
		"where")
		    if [ "$cur" != "${cur%%[=&]}" ]; then
			COMPREPLY=("")
		    else
			add_options "$cur" "== != &"
		    fi
		    ;;
		"cast")
		    local last_key=$(prev_keyword $COMP_CWORD ${words[@]})
		    if [ "$prev" == "\"(\"" -a ! -z "$cur" ]; then
			select_options "$cur"
		    elif [ "$prev" == "buckets" ]; then
			COMPREPLY=("=")
		    elif [ "$last_key" == "=" ]; then
			if [ "$prev" != "=" ]; then
			    COMPREPLY=("')'")
			fi
		    elif [ "$last_key" != "as" ]; then
			COMPREPLY=("AS")
			update_completion "$cur" as
		    else
			    COMPREPLY=("')'")
		    fi
		    ;;
		*)
		    return 1
	    esac
	    ;;
    esac
    return 0
}
