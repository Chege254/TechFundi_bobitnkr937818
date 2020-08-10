
# virtualenv-activator <http://github.com/jnrbsn/virtualenv-activator>
# This file must be *sourced* using ``. etc/activate.sh``. You cannot run it directly.


# Only allow bash
if [[ -z "${BASH_SOURCE}" ]]; then
    echo "Don't be ridiculous. Use bash." >&2
    return 1
fi

deactivate () {
    __OLDPWD="${OLDPWD}"; cd "${VIRTUAL_ENV}"

    # Save a list of current environment variables
    env | awk -F"=" '{print $1}' | sort > tmp/post_activate_variables.$$
    # Save a list of current aliases
    alias | awk '{print $2}' | awk -F"=" '{print $1}' | sort > tmp/post_activate_aliases.$$
    # Save a list of current functions
    declare -F | awk '{print $NF}' | sort > tmp/post_activate_functions.$$

    # Unset any environment variables that didn't exist before activation
    for i in $(comm -13 tmp/pre_activate_variables.$$ tmp/post_activate_variables.$$); do unset $i; done
    # Unset any aliases that didn't exist before activation
    for i in $(comm -13 tmp/pre_activate_aliases.$$ tmp/post_activate_aliases.$$); do unalias $i; done
    # Unset any functions that didn't exist before activation
    for i in $(comm -13 tmp/pre_activate_functions.$$ tmp/post_activate_functions.$$); do unset -f $i; done

    # Restore the previously saved shell environment
    source tmp/pre_activate_environment.$$

    # Cleanup temporary files
    shopt -s nullglob
    rm -f tmp/{pre,post}_activate_*.$$
    shopt -u nullglob

    # Fix PWD and OLDPWD
    cd - > /dev/null; OLDPWD="${__OLDPWD}"; unset __OLDPWD
    # Clear cache used for PATH lookups
    hash -r 2> /dev/null

    # Self destruct!
    unset -f deactivate
}

__OLDPWD="${OLDPWD}"; cd "$(dirname "${BASH_SOURCE}")/.."

# Create a temporary directory
if [[ ! -d tmp ]]; then
    mkdir tmp
else
    # Clean up temporary files for processes that no longer exist
    shopt -s nullglob
    for i in tmp/{pre,post}_activate_* ; do
        if ! ps $(echo $i | awk -F"." '{print $NF}') > /dev/null; then
            rm -f $i
        fi
    done
    shopt -u nullglob
fi

if [[ -z "${VIRTUALENV_ACTIVATOR_SIMPLE}" ]]; then
    # Save a list of current environment variables
    env | awk -F"=" '{print $1}' | sort > tmp/pre_activate_variables.$$
    # Save a list of current aliases
    alias | awk '{print $2}' | awk -F"=" '{print $1}' | sort > tmp/pre_activate_aliases.$$
    # Save a list of current functions
    declare -F | awk '{print $NF}' | sort > tmp/pre_activate_functions.$$

    # Save the entire shell environment minus certain variables that we don't want to mess with
    set | grep -v "^BASH" \
        | grep -v "^\(__OLDPWD\)=" \
        | grep -v "^\(PWD\|OLDPWD\|EUID\|UID\|PPID\|SHELLOPTS\)=" \
        > tmp/pre_activate_environment.$$
else
    # These things don't make sense for simple mode
    export VIRTUAL_ENV_DISABLE_PROMPT=1
    unset -f deactivate
fi

# These are the two most important variables in your virtual environment
export VIRTUAL_ENV="$(pwd)"
export PATH="${VIRTUAL_ENV}/bin:${PATH}"

# Unset PYTHONHOME if set
if [[ -n "${PYTHONHOME}" ]]; then
    unset PYTHONHOME
fi

# Change the shell prompt unless explicitly disabled
if [[ -z "${VIRTUAL_ENV_DISABLE_PROMPT}" ]]; then
    # If the directory name is generic, use the parent directory name
    if [[ $(basename "${VIRTUAL_ENV}") =~ ^\.?v(irtual)?env$ ]]; then
        export PS1="($(basename "$(dirname "${VIRTUAL_ENV}")")) ${PS1}"
    else
        export PS1="($(basename "${VIRTUAL_ENV}")) ${PS1}"
    fi
fi

# Make the virtual environment relocatable
virtualenv --relocatable "${VIRTUAL_ENV}" > /dev/null 2>&1

# Fix pydoc and pip to work well with the virtual environment
alias pydoc="python -m pydoc"
function pip () { python -m pip "$@"; virtualenv --relocatable "${VIRTUAL_ENV}" > /dev/null 2>&1; }

# Include any extra stuff in the environment
if [[ -f etc/environment.sh ]]; then
    source etc/environment.sh
fi

# Fix PWD and OLDPWD
cd - > /dev/null; OLDPWD="${__OLDPWD}"; unset __OLDPWD
# Clear cache used for PATH lookups
hash -r 2> /dev/null
