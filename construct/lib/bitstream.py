from io import BlockingIOError
from time import sleep
from sys import maxsize


class RestreamedBytesIO(object):

    def __init__(self, substream, decoder, decoderunit, encoder, encoderunit):
        self.substream = substream
        self.encoder = encoder
        self.encoderunit = encoderunit
        self.decoder = decoder
        self.decoderunit = decoderunit
        self.rbuffer = b""
        self.wbuffer = b""
        self.sincereadwritten = 0
        self.rhistory = None
        self.rhistorystart = 0

    def read(self, count=None):
        if count is None:
            while True:
                data = self.substream.read(self.decoderunit)
                if data is None or len(data) == 0:
                    break
                self.rbuffer += self.decoder(data)
            data, self.rbuffer = self.rbuffer, b''
            if self.rhistory is not None:
                self.rhistory += data
            self.sincereadwritten += len(data)
            return data

        else:
            if count < 0:
                raise ValueError("count cannot be negative")
            while len(self.rbuffer) < count:
                data = self.substream.read(self.decoderunit)
                if data is None or len(data) == 0:
                    return b''
                self.rbuffer += self.decoder(data)
            data, self.rbuffer = self.rbuffer[:count], self.rbuffer[count:]
            if self.rhistory is not None:
                self.rhistory += data
            self.sincereadwritten += count
            return data

    def write(self, data):
        self.wbuffer += data
        datalen = len(data)
        while len(self.wbuffer) >= self.encoderunit:
            data, self.wbuffer = self.wbuffer[:self.encoderunit], self.wbuffer[self.encoderunit:]
            self.substream.write(self.encoder(data))
        self.sincereadwritten += datalen
        return datalen

    def close(self):
        if len(self.rbuffer):
            raise ValueError("closing stream but %d unread bytes remain, %d is decoded unit" % (len(self.rbuffer), self.decoderunit))
        if len(self.wbuffer):
            raise ValueError("closing stream but %d unwritten bytes remain, %d is encoded unit" % (len(self.wbuffer), self.encoderunit))

    def seek(self, at, whence=0):
        if whence == 0:
            if at == self.sincereadwritten:
                pass
            elif self.rhistory is not None and self.rhistorystart <= at < self.sincereadwritten:
                rewind = self.sincereadwritten - at
                self.rbuffer = self.rhistory[len(self.rhistory)-rewind:] + self.rbuffer
                self.rhistory = self.rhistory[:len(self.rhistory)-rewind]
                self.sincereadwritten = at
            else:
                raise IOError
        else:
            raise IOError

    def seekable(self):
        return False

    def tell(self):
        """WARNING: tell is correct only on read-only and write-only instances."""
        return self.sincereadwritten

    def tellable(self):
        return True

    def atomic_bookmark(self):
        """
        Marks the current read position so that a later seek() can return to it, and returns the marker (a tell() value). Consumed data is retained in memory until atomic_release() is called with a marker equal or older. Used internally to implement atomic parsing of nested structures. Bookmarks can be nested, only the oldest marker retains data.
        """
        if self.rhistory is None:
            self.rhistory = b""
            self.rhistorystart = self.sincereadwritten
        return self.sincereadwritten

    def atomic_release(self, marker):
        """
        Drops the data retained since the marker was obtained from atomic_bookmark(). Should be called once the marked region is no longer needed, otherwise retained data grows without bound.
        """
        if self.rhistory is not None and marker <= self.rhistorystart:
            self.rhistory = None
            self.rhistorystart = 0


class RebufferedBytesIO(object):

    def __init__(self, substream, tailcutoff=None):
        self.substream = substream
        self.offset = 0
        self.rwbuffer = b""
        self.moved = 0
        self.tailcutoff = tailcutoff

    def read(self, count=None):
        if count is None:
            raise ValueError("count must be integer, reading until EOF not supported")
        startsat = self.offset
        endsat = startsat + count
        if startsat < self.moved:
            raise IOError("could not read because tail was cut off")
        while self.moved + len(self.rwbuffer) < endsat:
            try:
                newdata = self.substream.read(128*1024)
            except BlockingIOError:
                newdata = None
            if not newdata:
                sleep(0)
                continue
            self.rwbuffer += newdata
        data = self.rwbuffer[startsat-self.moved:endsat-self.moved]
        self.offset += count
        if self.tailcutoff is not None and self.moved < self.offset - self.tailcutoff:
            removed = self.offset - self.tailcutoff - self.moved
            self.moved += removed
            self.rwbuffer = self.rwbuffer[removed:]
        if len(data) < count:
            raise IOError("could not read enough bytes, something went wrong")
        return data

    def write(self, data):
        startsat = self.offset
        endsat = startsat + len(data)
        while self.moved + len(self.rwbuffer) < startsat:
            newdata = self.substream.read(128*1024)
            self.rwbuffer += newdata
            if not newdata:
                sleep(0)
        self.rwbuffer = self.rwbuffer[:startsat-self.moved] + data + self.rwbuffer[endsat-self.moved:]
        self.offset = endsat
        if self.tailcutoff is not None and self.moved < self.offset - self.tailcutoff:
            removed = self.offset - self.tailcutoff - self.moved
            self.moved += removed
            self.rwbuffer = self.rwbuffer[removed:]
        return len(data)

    def seek(self, at, whence=0):
        if whence == 0:
            self.offset = at
            return self.offset
        elif whence == 1:
            self.offset += at
            return self.offset
        else:
            raise ValueError("this class seeks only with whence: 0 and 1 (excluded 2)")

    def seekable(self):
        return True

    def tell(self):
        return self.offset

    def tellable(self):
        return True

    def cachedfrom(self):
        return self.moved

    def cachedto(self):
        return self.moved + len(self.rwbuffer)
