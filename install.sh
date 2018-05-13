#!/bin/sh

script="source $(pwd)/src/python-module/sac.py\n\ndefine hook-stop\nsac\nend"

# Ask for the permission to edit the first argument
ask_permission() {
    read -p "This script will concatenate text to \"$1\".
Do you wish to continue ? (y/n) " answer

    if [ "${answer:0:1}" != "y" ] && [ "${answer:0:1}" != "Y" ]; then
      echo "Understood, exiting installer script..."
      return 1
    fi

    return 0
}

# Check if the file given in argument already contains $script
is_configured() {
    grep "$(echo -e "$script")" "$1" 1> /dev/null 2> /dev/null \
        && echo "$gdbinit already configured" \
        && return 0

    return 1
}

gdbinit="$HOME/.gdbinit"
[ $# -eq 1 ] && gdbinit="$1"

# Ask the user to modify $gdbinit
ask_permission "$1" || exit 1

# Check if the file is already configured
is_configured "$gdbinit" && exit 1

# Put the script in $gdbinit
echo 1>&2 "[Configuring $gdbinit]"
echo -e "$script" >> "$gdbinit"
echo 1>&2 "[Done]"

exit 0
