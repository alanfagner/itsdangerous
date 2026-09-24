import hashlib
from functools import partial

import pytest

from itsdangerous.exc import BadSignature
from itsdangerous.signer import HMACAlgorithm
from itsdangerous.signer import NoneAlgorithm
from itsdangerous.signer import Signer
from itsdangerous.signer import SigningAlgorithm


class _ReverseAlgorithm(SigningAlgorithm):
    def get_signature(self, key, value):
        return (key + value)[::-1]


class TestSigner:
    @pytest.fixture()
    def signer_factory(self):
        return partial(Signer, secret_key="secret-key")

    @pytest.fixture()
    def signer(self, signer_factory):
        return signer_factory()

    def test_signer(self, signer):
        signed = signer.sign("my string")
        assert isinstance(signed, bytes)
        assert signer.validate(signed)
        out = signer.unsign(signed)
        assert out == b"my string"

    def test_no_separator(self, signer):
        signed = signer.sign("my string")
        signed = signed.replace(signer.sep, b"*", 1)
        assert not signer.validate(signed)

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_broken_signature(self, signer):
        signed = signer.sign("b")
        bad_signed = signed[:-1]
        bad_sig = bad_signed.rsplit(b".", 1)[1]
        assert not signer.verify_signature(b"b", bad_sig)

        with pytest.raises(BadSignature) as exc_info:
            signer.unsign(bad_signed)

        assert exc_info.value.payload == b"b"

    def test_changed_value(self, signer):
        signed = signer.sign("my string")
        signed = signed.replace(b"my", b"other", 1)
        assert not signer.validate(signed)

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_invalid_separator(self, signer_factory):
        with pytest.raises(ValueError) as exc_info:
            signer_factory(sep="-")

        assert "separator cannot be used" in str(exc_info.value)

    @pytest.mark.parametrize(
        "key_derivation", ("concat", "django-concat", "hmac", "none")
    )
    def test_key_derivation(self, signer_factory, key_derivation):
        signer = signer_factory(key_derivation=key_derivation)
        assert signer.unsign(signer.sign("value")) == b"value"

    def test_invalid_key_derivation(self, signer_factory):
        with pytest.raises(ValueError) as exc_info:
            signer_factory(key_derivation="invalid")

        message = str(exc_info.value)
        assert "invalid" in message

        for supported in ("concat", "django-concat", "hmac", "none"):
            assert supported in message

    def test_digest_method(self, signer_factory):
        signer = signer_factory(digest_method=hashlib.md5)
        assert signer.unsign(signer.sign("value")) == b"value"

    @pytest.mark.parametrize(
        "digest_method", ("sha256", b"sha256", 42, hashlib.sha256())
    )
    def test_non_callable_digest_method_rejected(self, signer_factory, digest_method):
        with pytest.raises(TypeError) as exc_info:
            signer_factory(digest_method=digest_method)

        message = str(exc_info.value)
        assert "digest_method" in message
        assert repr(digest_method) in message

    @pytest.mark.parametrize(
        "algorithm", (None, NoneAlgorithm(), HMACAlgorithm(), _ReverseAlgorithm())
    )
    def test_algorithm(self, signer_factory, algorithm):
        signer = signer_factory(algorithm=algorithm)
        assert signer.unsign(signer.sign("value")) == b"value"

        if algorithm is None:
            assert signer.algorithm.digest_method == signer.digest_method

    def test_empty_secret_key_rejected(self):
        with pytest.raises(ValueError):
            Signer("")

        with pytest.raises(ValueError):
            Signer(b"")

    def test_empty_secret_key_message_names_cause(self):
        with pytest.raises(ValueError) as exc_info:
            Signer("")

        message = str(exc_info.value)
        assert "secret key" in message
        assert "empty" in message

    def test_key_collection_without_usable_secret_rejected(self):
        for secret_key in ([], (), iter([]), ["", ""]):
            with pytest.raises(ValueError):
                Signer(secret_key)

        assert Signer(["", "real-key"]).secret_key == b"real-key"

    def test_non_empty_secret_key_output_unchanged(self):
        signer = Signer("secret-key")
        assert signer.secret_keys == [b"secret-key"]
        assert signer.sign("my string") == b"my string.wh6tMHxLgJqB6oY1uT73iMlyrOA"

    def test_secret_keys(self):
        signer = Signer("a")
        signed = signer.sign("my string")
        assert isinstance(signed, bytes)

        signer = Signer(["a", "b"])
        assert signer.validate(signed)
        out = signer.unsign(signed)
        assert out == b"my string"


def test_abstract_algorithm():
    alg = SigningAlgorithm()

    with pytest.raises(NotImplementedError):
        alg.get_signature(b"a", b"b")
