from oidc_sts_bridge.utils import is_stringable


def test_is_stringable_string():
    """Test is_stringable with string inputs."""
    assert is_stringable("hello") is True
    assert is_stringable("") is True
    assert is_stringable("123") is True
    assert is_stringable("special chars: @#") is True


def test_is_stringable_integer():
    """Test is_stringable with integer inputs."""
    assert is_stringable(123) is True
    assert is_stringable(0) is True
    assert is_stringable(-456) is True
    assert is_stringable(2**64) is True  # Large integer


def test_is_stringable_float():
    """Test is_stringable with float inputs."""
    assert is_stringable(3.14) is True
    assert is_stringable(0.0) is True
    assert is_stringable(-2.5) is True
    assert is_stringable(float("inf")) is True  # Infinity
    assert is_stringable(float("-inf")) is True
    assert is_stringable(float("nan")) is True  # NaN


def test_is_stringable_boolean():
    """Test is_stringable with boolean inputs."""
    assert is_stringable(True) is True
    assert is_stringable(False) is True


def test_is_stringable_unsupported_types():
    """Test is_stringable with unsupported types."""
    assert is_stringable(None) is False
    assert is_stringable([1, 2, 3]) is False
    assert is_stringable({"key": "value"}) is False
    assert is_stringable((1, 2)) is False
    assert is_stringable(set([1, 2])) is False
    assert is_stringable(lambda x: x) is False
    assert is_stringable(object()) is False


def test_is_stringable_custom_object_str_failure():
    """Test is_stringable with a custom object where str() raises an exception."""

    class BadStrObject:
        def __str__(self):
            raise ValueError("Cannot convert to string")

    assert is_stringable(BadStrObject()) is False


def test_is_stringable_custom_object_valid_str():
    """Test is_stringable with a custom object that is not a supported type."""

    class GoodStrObject:
        def __str__(self):
            return "valid"

    assert is_stringable(GoodStrObject()) is False  # Not an int, float, bool, or str
