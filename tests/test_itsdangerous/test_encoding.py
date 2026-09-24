import pytest

from itsdangerous.encoding import base64_decode
from itsdangerous.encoding import base64_encode
from itsdangerous.encoding import bytes_to_int
from itsdangerous.encoding import int_to_bytes
from itsdangerous.encoding import want_bytes
from itsdangerous.exc import BadData


@pytest.mark.parametrize("value", ("mañana", b"tomorrow"))
def test_want_bytes(value):
    out = want_bytes(value)
    assert isinstance(out, bytes)


def test_want_bytes_encodes_text_with_requested_encoding():
    value = "mañana"
    assert want_bytes(value, encoding="latin-1") == value.encode("latin-1")
    lossy = "mañana∞"
    assert want_bytes(lossy, encoding="latin-1", errors="ignore") == lossy.encode(
        "latin-1", "ignore"
    )


def test_want_bytes_returns_bytes_unchanged():
    value = b"tomorrow"
    assert want_bytes(value) is value


@pytest.mark.parametrize("value", (None, 42, ["a"], bytearray(b"x")))
def test_want_bytes_rejects_other_types(value):
    with pytest.raises(TypeError):
        want_bytes(value)


@pytest.mark.parametrize("value", (None, 42))
def test_want_bytes_error_names_value(value):
    with pytest.raises(TypeError) as info:
        want_bytes(value)

    assert repr(value) in str(info.value)


@pytest.mark.parametrize("value", ("無限", b"infinite"))
def test_base64(value):
    enc = base64_encode(value)
    assert isinstance(enc, bytes)
    dec = base64_decode(enc)
    assert dec == want_bytes(value)


def test_base64_bad():
    with pytest.raises(BadData):
        base64_decode("12345")


@pytest.mark.parametrize(
    ("value", "expect"), ((0, b""), (192, b"\xc0"), (18446744073709551615, b"\xff" * 8))
)
def test_int_bytes(value, expect):
    enc = int_to_bytes(value)
    assert enc == expect
    dec = bytes_to_int(enc)
    assert dec == value


@pytest.mark.parametrize("value", (b"aGV*s b\nG8", "aGV*s b\nG8"))
def test_base64_decode_rejects_out_of_alphabet(value):
    with pytest.raises(BadData):
        base64_decode(value)
