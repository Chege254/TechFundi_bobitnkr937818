
import os, sys
import click
from .script import Script
import platform

if int(platform.python_version_tuple()[0]) < 3:
    version = 2
    import commands
else:
    version = 3
    import subprocess


@click.command()
@click.option('-p', '--path', help='path to shell')
@click.option('-s', '--shell', help='the name of the shell')
@click.option('--no-backup', help='choose to not make a backup of conf file', is_flag=True)
def install(path, shell, no_backup):
    if not path:
        if version == 3:
            path = subprocess.getoutput('which $SHELL')
        else:
            path = commands.getoutput('which $SHELL')

    if not shell:
        shell = path.split('/')[-1]

    home = os.getenv('HOME')

    if not no_backup:
        os.system('cp %s/.%src %s/.%src_backup' % (home, shell, home, shell))

    if not os.path.exists(os.path.join(home, '.%src' % (shell))):
        click.echo('No RC file found :: exiting')
        sys.exit(1)
    with open('%s/.%src' % (home, shell), 'a+') as f:
        f.write(Script)
    click.secho('DONE', fg='cyan', bold=True)

