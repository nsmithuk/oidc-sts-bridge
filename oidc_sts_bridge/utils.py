from typing import Any

def is_stringable(value: Any) -> bool:
    """Checks if a value can be converted to a (sensible) string.

    Args:
        value: The value to check (any type).

    Returns:
        bool: True if the value is an int, float, bool, or str and can be converted to a string
              via str(), False otherwise.

    Notes:
        - Used in AWS session tag validation to ensure claim and tag values are stringable,
          as required by AWS STS (e.g., for map_validate_merge_claims_and_tags).
        - Supports int, float, bool, and str, which cover typical JWT claim and tag values
          (e.g., numbers, booleans, strings).
        - Defensively handles rare cases where str() might raise an exception, ensuring
          robustness for unexpected inputs.
        - Non-stringable types (e.g., dict, list, None) return False immediately to optimise
          performance and avoid unnecessary str() attempts.
    """
    # Check if the value is a supported type that can typically be converted to a string.
    if isinstance(value, (int, float, bool, str)):
        try:
            # Attempt to convert the value to a string to confirm it's stringable.
            str(value)
            return True
        except (ValueError, TypeError):
            # Handle specific exceptions that might occur during string conversion.
            # This ensures defensive handling without catching unexpected errors.
            return False
    # Return False for unsupported types (e.g., dict, list, None) without attempting str().
    return False