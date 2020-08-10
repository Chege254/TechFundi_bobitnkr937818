import click
import sys

from python_hosts.hosts import Hosts, HostsEntry
from python_hosts.exception import UnableToWriteHosts


PROFILE_SITES = {
    "SOCIAL": [
        "www.facebook.com",
        "twitter.com",
        "www.reddit.com",
        "www.instagram.com",
        "www.goodreads",
        "www.snapchat",
        "vk.com",
        "www.flickr.com",
        "www.linkedin.com",
        "www.pinterest.com",
        "www.tumblr.com",
        "www.reddit.com",
    ],
    "MEME": ["9gag.com", "www.4chan.com"],
    "NEWS": [
        "news.ycombinator.com",
        "blic.rs",
        "news.yahoo.com",
        "news.google.com",
        "www.huffpost.com",
        "edition.cnn.com",
        "www.foxnews.com",
        "www.dailymail.co.uk",
        "www.washingtonpost.com",
        "www.wsj.com",
        "www.bbc.com",
        "www.usatoday.com",
        "www.latimes.com",
    ],
    "BLOGS": ["www.buzzfeed.com", "ispovesti.com"],
    "ESPORTS": ["www.hltv.org", "www.twitch.tv"],
    "PORN": [],
    "PIRATE": ["yts.ag"],
}

pass_hosts = click.make_pass_decorator(Hosts)
flatten = lambda l: [item for sublist in l for item in sublist]


def find_hosts_path():
    """
    Determines hosts file path based on detected operating system.
    """

    HOSTS_PATH = None
    if sys.platform in ("win32", "cygwin"):
        # TODO MIGHT NOT WORK ON EVERY SYSTEM!!!
        HOSTS_PATH = "C:/Windows/System32/drivers/etc/hosts"
    else:
        HOSTS_PATH = "/etc/hosts"

    return HOSTS_PATH


@click.group()
@click.pass_context
def cli(ctx):
    """
    A simple tool for blocking access to distracting websites, such as social media websites,
    news webistes, streaming services etc. This tools relies on modifying the hosts file.
    
    It is not meant to be bullet-proof, but to provide easy way to break annoying habits 
    and increase productivity.

    Example usage for blocking all available webistes:
    block-hosts block-all
    """

    ctx.obj = Hosts(find_hosts_path())


@cli.command(help="Block all sites from the curated list of sites.")
@pass_hosts
def block_all(hosts):
    all_sites = flatten(list(PROFILE_SITES.values()))
    for site in all_sites:
        new_entry = HostsEntry(entry_type="ipv4", address="127.0.0.1", names=[site])
        hosts.add([new_entry])

    try:
        hosts.write()
        print("All websites in a curated list have been blocked.")
        print("Some websites require browser restart for changes to take effect.")
        print("To see the list of blocked websites, run 'block-hosts list-websites'")
    except UnableToWriteHosts:
        print(
            "Unable to write to hosts file. Make sure Block has administrator privileges."
        )


@cli.command(help="Block several websites under a single profile.")
@click.argument("profile")
@pass_hosts
def block_profile(hosts, profile):
    profile = str.upper(profile)

    if profile in PROFILE_SITES:
        for site in PROFILE_SITES[profile]:
            new_entry = HostsEntry(entry_type="ipv4", address="127.0.0.1", names=[site])
            hosts.add([new_entry])
    else:
        print("No such profile exists, please try again.")
        print("To see a list of available profiles, type 'block-hosts list-profiles'")

    try:
        hosts.write()
        print(f"Websites from profile '{profile}' have been blocked.")
        print("Some websites require browser restart for changes to take effect.")
        print(
            f"To see a list of websites blocked by current profile, type 'block list-websites -p '{profile}'"
        )
    except UnableToWriteHosts:
        print(
            "Unable to write to hosts file. Make sure Block has administrator privileges."
        )


@cli.command(help="Block a single site.")
@click.argument("site")
@pass_hosts
def block_single(hosts, site):
    new_entry = HostsEntry(entry_type="ipv4", address="127.0.0.1", names=[site])
    hosts.add([new_entry])

    try:
        hosts.write()
        print(f"Website '{site}' has been blocked.")
        print("Some websites require browser restart for changes to take effect.")
    except UnableToWriteHosts:
        print(
            "Unable to write to hosts file. Make sure Block has administrator privileges."
        )


@cli.command(help="Unblock all blocked websites.")
@pass_hosts
def unblock_all(hosts):
    all_sites = flatten(list(PROFILE_SITES.values()))
    for site in all_sites:
        hosts.remove_all_matching(name=site)

    try:
        hosts.write()
        print("All websites have been unblocked.")
        print("Some websites require browser restart for changes to take effect.")
        print("To see the list of unblocked websites, run 'block-hosts list-websites'")
    except UnableToWriteHosts:
        print(
            "Unable to write to hosts file. Make sure Block has administrator privileges."
        )


@cli.command(help="Unblock the specified profile.")
@click.argument("profile")
@pass_hosts
def unblock_profile(hosts, profile):
    profile = str.upper(profile)
    for site in PROFILE_SITES[profile]:
        hosts.remove_all_matching(name=site)

    try:
        hosts.write()
        print(f"All websites from profile '{profile}' have been unblocked.")
        print("Some websites require browser restart for changes to take effect.")
        print(
            f"To see a list of websites blocked by current profile, type 'block list-websites -p '{profile}'"
        )
    except UnableToWriteHosts:
        print(
            "Unable to write to hosts file. Make sure Block has administrator privileges."
        )


@cli.command(help="Unblock a single website.")
@click.argument("site")
@pass_hosts
def unblock_single(hosts, site):
    hosts.remove_all_matching(name=site)
    try:
        hosts.write()
        print(f"Website {site} has been unblocked.")
        print("Some websites require browser restart for changes to take effect.")
    except UnableToWriteHosts:
        print(
            "Unable to write to hosts file. Make sure Block has administrator privileges."
        )


@cli.command(help="Show a complete list of default websites.")
@click.option(
    "-p",
    "--profile",
    default=None,
    help="List all websites curated under the specified profile.",
)
def list_websites(profile):

    # TODO check if profile exists
    if profile is not None:
        profile = str.upper(profile)
        print(f"The following is a curated list of websites for profile '{profile}'")
        for site in PROFILE_SITES[profile]:
            print(site)
    else:
        print(
            "The following is a curated list of websites that will be blocked by default."
        )
        all_sites = flatten(list(PROFILE_SITES.values()))
        for site in all_sites:
            print(site)


@cli.command(help="Show a list of available profiles.")
def list_profiles():
    """
    Prints a list of all available profiles for blocking."
    """

    print("Complete list of available profiles:")
    for profile in PROFILE_SITES:
        print(profile)


@cli.command(help="Show the location of used hosts file.")
@pass_hosts
def show_hosts(hosts):
    """
    Prints the location of hosts file on the filesystem. Value changes depeding on the
    underlying operating system.

    On UNIX-based systems such as macOS and Linux, usually it is '/etc/hosts'.
    On Windows, usually it is 'C:/Windows/System32/drivers/etc/hosts'
    """

    print(f"Using hosts file located in: {hosts.hosts_path}")


if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter

