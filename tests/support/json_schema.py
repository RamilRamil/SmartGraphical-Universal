"""Minimal JSON Schema (draft-07 subset) validator.

The published analyzer contract must actually be checked against real output,
not merely committed. Adding `jsonschema` for that would put a dependency in the
test path that the analyzer image itself does not have, so the subset the
contract uses -- type, required, properties, additionalProperties, items, enum,
const, oneOf, $ref to #/definitions/* -- is implemented here instead.

Returns a list of human-readable error strings; empty means valid.
"""

_TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def validate(instance, schema, root=None, path="$"):
    root = root if root is not None else schema
    errors = []

    if "$ref" in schema:
        return validate(instance, _resolve(schema["$ref"], root), root, path)

    if "oneOf" in schema:
        matches = [s for s in schema["oneOf"] if not validate(instance, s, root, path)]
        if len(matches) != 1:
            errors.append(f"{path}: matched {len(matches)} of {len(schema['oneOf'])} oneOf branches, expected 1")
        return errors

    expected_type = schema.get("type")
    if expected_type is not None:
        python_type = _TYPE_MAP[expected_type]
        # bool is a subclass of int in Python; the contract never means that.
        if expected_type in ("integer", "number") and isinstance(instance, bool):
            errors.append(f"{path}: expected {expected_type}, got boolean")
            return errors
        if not isinstance(instance, python_type):
            errors.append(f"{path}: expected {expected_type}, got {type(instance).__name__}")
            return errors

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']!r}")

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key!r}")
        for key, value in instance.items():
            if key in properties:
                errors.extend(validate(value, properties[key], root, f"{path}.{key}"))

    if isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            errors.extend(validate(item, schema["items"], root, f"{path}[{index}]"))

    return errors


def _resolve(ref, root):
    if not ref.startswith("#/"):
        raise ValueError(f"only local refs are supported, got {ref!r}")
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node
