if bytes is str:
    def bytes2str(bstr):
        assert isinstance(bstr, bytes)
        return bstr
    def str2bytes(sstr):
        assert isinstance(sstr, str)
        return sstr
    def textopen(filename, mode):
        return open(filename, mode)
else:
    def bytes2str(bstr):
        assert isinstance(bstr, bytes)
        return bstr.decode("iso-8859-1") # always successful
    def str2bytes(sstr):
        assert isinstance(sstr, str)
        return sstr.encode("iso-8859-1") # might fail, but spec says it doesn't
    def textopen(filename, mode):
        # We use the same encoding as for all wsgi strings here.
        return open(filename, mode, encoding="iso-8859-1")
