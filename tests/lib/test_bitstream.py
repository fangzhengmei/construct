from tests.declarativeunittest import *
from construct.lib.bitstream import *


def test_restreamed():
    # tested by Bitwise Bytewise ByteSwapped BitsSwapped cases
    pass

def test_restreamed_atomic_bookmark():
    from construct.lib.binary import bytes2bits, bits2bytes

    # seeking back to a bookmark re-reads retained data without re-consuming the substream
    substream = io.BytesIO(b"\x02ab")
    stream = RestreamedBytesIO(substream, bytes2bits, 1, bits2bytes, 8)
    marker = stream.atomic_bookmark()
    assert marker == 0
    first = stream.read(16)
    assert substream.tell() == 2
    stream.seek(marker)
    assert stream.tell() == 0
    assert substream.tell() == 2
    assert stream.read(16) == first
    assert substream.tell() == 2
    stream.atomic_release(marker)
    assert stream.rhistory is None
    stream.read(8)
    assert substream.tell() == 3

    # nested bookmarks: inner release does not drop data retained for the outer marker
    stream = RestreamedBytesIO(io.BytesIO(b"\xff\xff\xff\xff"), bytes2bits, 1, bits2bytes, 8)
    outer = stream.atomic_bookmark()
    stream.read(8)
    inner = stream.atomic_bookmark()
    stream.read(8)
    stream.atomic_release(inner)
    assert stream.rhistory is not None
    stream.seek(outer)
    assert stream.tell() == 0
    stream.atomic_release(outer)
    assert stream.rhistory is None

    # without a bookmark, seeking backwards is still not allowed
    stream = RestreamedBytesIO(io.BytesIO(b"\xff\xff"), bytes2bits, 1, bits2bytes, 8)
    stream.read(8)
    stream.seek(8)
    assert raises(stream.seek, 0) == IOError

def test_rebuffered():
    z = b"0"

    print("sequential read")
    bstream = RebufferedBytesIO(io.BytesIO(z*1000))
    assert bstream.read(1000) == z*1000

    print("random reads")
    data = os.urandom(1000)
    bstream = RebufferedBytesIO(io.BytesIO(data))
    for i in range(50):
        o1 = random.randrange(0, 480)
        o2 = random.randrange(520, 1000)
        assert bstream.seek(o1) == o1
        assert bstream.tell() == o1
        assert bstream.read(o2-o1) == data[o1:o2]
        assert bstream.tell() == o2

    print("sequential writes")
    bstream = RebufferedBytesIO(io.BytesIO())
    for i in range(10):
        assert bstream.write(z*100) == 100
    assert bstream.seek(0) == 0
    assert bstream.read(1000) == z*1000

    print("random writes")
    data = os.urandom(1000)
    bstream = RebufferedBytesIO(io.BytesIO())
    assert bstream.write(data) == len(data)
    for i in range(50):
        o1 = random.randrange(0, 480)
        o2 = random.randrange(520, 1000)
        assert bstream.seek(o1) == o1
        assert bstream.tell() == o1
        assert bstream.write(data[o1:o2]) == o2-o1
        assert bstream.tell() == o2
    assert bstream.seek(0) == 0
    assert bstream.read(len(data)) == data

    print("cutting off trail")
    data = os.urandom(1000)
    bstream = RebufferedBytesIO(io.BytesIO(data), tailcutoff=50)
    for i in range(15):
        at = bstream.tell()
        assert bstream.read(50) == data[at:at+50]
        jumpback = random.randrange(1, 19)
        assert bstream.seek(-jumpback, 1)
