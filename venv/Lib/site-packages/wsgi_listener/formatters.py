from datetime import datetime as dt

from .timehacks import Local


def standard_formatter(status_code, environ, content_length):
    return "{0} {1}".format(dt.now().isoformat(), status_code)


# noinspection PyPep8Naming
def ApacheFormatter(with_response_time=True):
    """ A factory that returns the wanted formatter """
    if with_response_time:
        return ApacheFormatters.format_with_response_time
    else:
        return ApacheFormatters.format_NCSA_log


# noinspection PyPep8Naming
class ApacheFormatters(object):
    @staticmethod
    def format_NCSA_log(status_code, environ, content_length, **kwargs):
        """
          Apache log format 'NCSA extended/combined log':
          "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""
          see http://httpd.apache.org/docs/current/mod/mod_log_config.html#formats
        """

        # Let's collect log values
        val = dict()
        ip_header = kwargs.get('ip_header', None)
        if ip_header:
            try:
                val['host'] = environ.get(ip_header, '')
            except:
                val['host'] = environ.get('REMOTE_ADDR', '')
        else:
            val['host'] = environ.get('REMOTE_ADDR', '')
        val['logname'] = '-'
        val['user'] = '-'
        date = dt.now(tz=Local)
        month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][date.month - 1]
        val['time'] = date.strftime("%d/{0}/%Y:%H:%M:%S %z".format(month))
        val['request'] = "{0} {1} {2}".format(
              environ.get('REQUEST_METHOD', ''),
              environ.get('PATH_INFO', ''),
              environ.get('SERVER_PROTOCOL', '')
            )
        val['status'] = status_code
        val['size'] = content_length
        val['referer'] = environ.get('HTTP_REFERER', '')
        val['agent'] = environ.get('HTTP_USER_AGENT', '')

        # see http://docs.python.org/3/library/string.html#format-string-syntax
        FORMAT = '{host} {logname} {user} [{time}] "{request}" '
        FORMAT += '{status} {size} "{referer}" "{agent}"'
        return FORMAT.format(**val)

    @staticmethod
    def format_with_response_time(*args, **kwargs):
        """
          The dict kwargs should contain 'rt_us', the response time in milliseconds.
          This is the format for TinyLogAnalyzer:
          https://pypi.python.org/pypi/TinyLogAnalyzer
        """
        rt_us = kwargs.get('rt_us')
        return ApacheFormatters.format_NCSA_log(*args, **kwargs) + " {0}/{1}".format(int(rt_us/1000000), rt_us)
