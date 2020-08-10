
Script = '''
function cd() {
  builtin cd "$@"

  if [[ -z "$VIRTUAL_ENV" ]] ; then
      if [[ -d ./venv ]] ; then
        echo ":: Activating virtual environment"
        source ./venv/bin/activate
      fi
  else
      parentdir="$(dirname "$VIRTUAL_ENV")"
      if [[ "$PWD"/ != "$parentdir"/* ]] ; then
        echo ":: Deactivating virtual environment"
        deactivate
      fi
  fi
}
'''

