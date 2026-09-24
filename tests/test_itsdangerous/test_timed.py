from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import partial

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from test_itsdangerous.test_serializer import TestSerializer
from test_itsdangerous.test_signer import TestSigner


class FreezeMixin:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft


class TestTimestampSigner(FreezeMixin, TestSigner):
    @pytest.fixture()
    def signer_factory(self):
        return partial(TimestampSigner, secret_key="secret-key")

    def test_max_age(self, signer, ts, freeze):
        signed = signer.sign("value")
        freeze.tick()
        assert signer.unsign(signed, max_age=10) == b"value"
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            signer.unsign(signed, max_age=10)

        assert exc_info.value.date_signed == ts

    def test_return_timestamp(self, signer, ts):
        signed = signer.sign("value")
        assert signer.unsign(signed, return_timestamp=True) == (b"value", ts)

    def test_timestamp_missing(self, signer):
        other = Signer("secret-key")
        signed = other.sign("value")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "missing" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_timestamp(self, signer):
        other = Signer("secret-key")
        signed = other.sign(b"value.____________")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_future_timestamp(self, signer):
        signed = b"value.TgPVoaGhoQ.AGBfQ6G6cr07byTRt0zAdPljHOY"

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_future_age(self, signer):
        signed = signer.sign("value")

        with freeze_time("1971-05-31"):
            with pytest.raises(SignatureExpired) as exc_info:
                signer.unsign(signed, max_age=10)

        assert isinstance(exc_info.value.date_signed, datetime)

    def test_sig_error_date_signed(self, signer):
        signed = signer.sign("my string").replace(b"my", b"other", 1)

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert isinstance(exc_info.value.date_signed, datetime)

    def test_unsign_refuses_nan_max_age(self, signer, freeze):
        signed = signer.sign("value")
        freeze.tick(timedelta(seconds=3600))

        with pytest.raises(ValueError) as exc_info:
            signer.unsign(signed, max_age=float("nan"))

        message = str(exc_info.value)
        assert "max_age" in message
        assert "nan" in message

    @pytest.mark.parametrize("max_age", ["10", b"10", [10], 10j, None.__class__])
    def test_unsign_refuses_non_real_max_age(self, signer, max_age):
        signed = signer.sign("value").replace(b"value", b"other", 1)

        with pytest.raises(TypeError) as exc_info:
            signer.unsign(signed, max_age=max_age)

        message = str(exc_info.value)
        assert "max_age" in message
        assert repr(max_age) in message

    @pytest.mark.parametrize("max_age", [None, 0, 10, float("inf")])
    def test_unsign_accepts_valid_max_age_values(self, signer, freeze, max_age):
        signed = signer.sign("value")
        assert signer.unsign(signed, max_age=max_age) == b"value"

        freeze.tick(timedelta(seconds=3600))

        if max_age is None or max_age == float("inf"):
            assert signer.unsign(signed, max_age=max_age) == b"value"
        else:
            with pytest.raises(SignatureExpired):
                signer.unsign(signed, max_age=max_age)


class TestTimedSerializer(FreezeMixin, TestSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(TimedSerializer, secret_key="secret_key")

    def test_max_age(self, serializer, value, ts, freeze):
        signed = serializer.dumps(value)
        freeze.tick()
        assert serializer.loads(signed, max_age=10) == value
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            serializer.loads(signed, max_age=10)

        assert exc_info.value.date_signed == ts
        assert serializer.load_payload(exc_info.value.payload) == value

    def test_loads_refuses_invalid_max_age(self, serializer, value):
        signed = serializer.dumps(value)

        with pytest.raises(ValueError) as nan_info:
            serializer.loads(signed, max_age=float("nan"))

        assert "max_age" in str(nan_info.value)
        assert "nan" in str(nan_info.value)

        with pytest.raises(TypeError) as type_info:
            serializer.loads(signed, max_age="10")

        assert "max_age" in str(type_info.value)
        assert "'10'" in str(type_info.value)

    def test_return_payload(self, serializer, value, ts):
        signed = serializer.dumps(value)
        assert serializer.loads(signed, return_timestamp=True) == (value, ts)
