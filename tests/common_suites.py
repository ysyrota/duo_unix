#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# common_suites.py
#

import re
import os
import subprocess
import time
import unittest
import sys
import urllib.request
import urllib.parse
import ssl

import pexpect
from config import (
    BAD_AUTOPUSH_VERIFIED_PUSH_CONF,
    BAD_CORRUPT_CONF,
    BAD_CORRUPT_SECURE_CONF,
    BAD_EMPTY_CONF,
    BAD_HEADER_CONF,
    BAD_MISSING_VALUES_CONF,
    MOCKDUO_AUTOPUSH,
    MOCKDUO_AUTOPUSH_SECURE,
    MOCKDUO_BADKEYS,
    MOCKDUO_BADKEYS_FAILSECURE,
    MOCKDUO_CONF,
    MOCKDUO_EXTRA_SPACE,
    MOCKDUO_FAILSECURE,
    MOCKDUO_FAILSECURE_BAD_CERT,
    MOCKDUO_FALLBACK,
    MOCKDUO_FIPS,
    MOCKDUO_NOVERIFY,
    MOCKDUO_PROMPTS_1,
    MOCKDUO_PROXY,
    MOCKDUO_VERIFIED_PUSH,
    TESTCONF,
    TempConfig,
)
from mockduo_context import NORMAL_CERT, SELFSIGNED_CERT, WRONGHOST_CERT, MockDuo

from typing import Sequence

TESTDIR = os.path.realpath(os.path.dirname(__file__))

if sys.platform == "sunos5":
    # Solaris timesout filedescriptors rather than issuing an EOF but
    # still uses EOF to signal a user prompt
    EOF = pexpect.TIMEOUT
    PROMPT = pexpect.EOF
else:
    EOF = pexpect.EOF
    PROMPT = pexpect.EOF


def fips_available():
    returncode = subprocess.call(
        [os.path.join(TESTDIR, "is_fips_supported.sh")],
        stdout=subprocess.PIPE,
    )
    return returncode == 0


class CommonTestCase(unittest.TestCase):
    def assertRegexSomeline(self, result: Sequence[str], regex: str):
        found = False
        for line in result:
            if re.search(regex, line):
                found = True
                break

        self.assertTrue(found, f"Regex '{regex}' not found in any lines of {result}")

    def call_binary(self, *args, **kwargs):
        raise NotImplementedError


# suite class just prevents the inner test cases from being run
class CommonSuites:
    class Configuration(CommonTestCase):
        def test_missing_config_file(self):
            """Missing conf file"""
            result = self.call_binary(["-d", "-c", "/nonexistent", "true"])
            self.assertRegexSomeline(
                result["stderr"],
                r"Couldn't open /nonexistent: No such file or directory",
            )

        def test_bad_permissions_on_conf_file(self):
            """Bad permissions on conf file"""
            with TempConfig(TESTCONF) as temp:
                os.chmod(temp.name, 0o644)
                result = self.call_binary(["-d", "-c", temp.name, "true"])
                self.assertRegexSomeline(
                    result["stderr"],
                    "{name} must be readable only by user '.*'".format(name=temp.name),
                )

        def test_bad_configuration_files(self):
            """Bad configuration files"""
            for config in [
                BAD_EMPTY_CONF,
                BAD_HEADER_CONF,
                BAD_MISSING_VALUES_CONF,
            ]:
                with TempConfig(config) as temp:
                    result = self.call_binary(["-d", "-c", temp.name, "true"])
                    self.assertRegexSomeline(
                        result["stderr"],
                        "Missing host, ikey, or skey in {name}".format(name=temp.name),
                    )

        def test_corrupt_configuration_file_failsafe(self):
            with TempConfig(BAD_CORRUPT_CONF) as temp:
                result = self.call_binary(["-d", "-c", temp.name, "true"])
                self.assertRegexSomeline(
                    result["stderr"], "Parse error in {name}".format(name=temp.name)
                )
                self.assertEqual(result["returncode"], 0)

        def test_corrupt_configuration_file_failsecure(self):
            with TempConfig(BAD_CORRUPT_SECURE_CONF) as temp:
                result = self.call_binary(["-d", "-c", temp.name, "true"])
                self.assertRegexSomeline(
                    result["stderr"], "Parse error in {name}".format(name=temp.name)
                )
                self.assertEqual(result["returncode"], 1)

        def test_autopush_with_verified_push(self):
            with TempConfig(BAD_AUTOPUSH_VERIFIED_PUSH_CONF) as temp:
                result = self.call_binary(["-d", "-c", temp.name, "true"])
                self.assertRegexSomeline(
                    result["stderr"], "autopush and verified_push cannot both be enabled in {name}".format(name=temp.name)
                )

    class DuoDown(CommonTestCase):
        def test_mockduo_down(self):
            """mockduo down"""
            with TempConfig(TESTCONF) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "whatever", "true"]
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Failsafe Duo login for 'whatever'.*: Couldn't connect to .*",
                )

        def test_down_fail_secure(self):
            """Test that binary fails secure if Duo is down"""
            # Weirdly this requires a bad cert. I think this may have been caused by some
            # file path confusion in the original cram test
            with TempConfig(MOCKDUO_FAILSECURE_BAD_CERT) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "whatever", "true"]
                )
                self.assertRegexSomeline(
                    result["stderr"], r"Couldn't open Duo API handle for .*"
                )
                self.assertEqual(result["returncode"], 1)

    class DuoSelfSignedCert(CommonTestCase):
        def run(self, result=None):
            with MockDuo(SELFSIGNED_CERT) as p:
                return super(CommonSuites.DuoSelfSignedCert, self).run(result)

        def test_invalid_cert(self):
            """Invalid cert"""
            for config in [MOCKDUO_CONF, MOCKDUO_FAILSECURE]:
                with TempConfig(config) as temp:
                    result = self.call_binary(
                        ["-d", "-c", temp.name, "-f", "whatever", "true"]
                    )
                    self.assertRegexSomeline(
                        result["stderr"],
                        r"{failmode} Duo login for .* Couldn't connect to .*: certificate verify failed".format(
                            failmode=config.failmode_as_prefix()
                        ),
                    )
                    if config.get("failmode", None) == "secure":
                        self.assertEqual(result["returncode"], 1)

        def test_self_signed_with_noverify(self):
            """With noverify"""
            with TempConfig(MOCKDUO_NOVERIFY) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"]
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Skipped Duo login for 'preauth-allow'.*: preauth-allowed",
                )

    class DuoBadCN(CommonTestCase):
        def run(self, result=None):
            with MockDuo(WRONGHOST_CERT):
                return super(CommonSuites.DuoBadCN, self).run(result)

        def test_wrong_hostname(self):
            """Wrong hostname"""
            for config in [MOCKDUO_CONF, MOCKDUO_FAILSECURE]:
                with TempConfig(config) as temp:
                    result = self.call_binary(
                        ["-d", "-c", temp.name, "-f", "whatever", "true"]
                    )
                    self.assertRegexSomeline(
                        result["stderr"],
                        r"{failmode} Duo login for .*: Couldn't connect to .*: Certificate name validation failed".format(
                            failmode=config.failmode_as_prefix()
                        ),
                    )
                    if config.get("failmode", None) == "secure":
                        self.assertEqual(result["returncode"], 1)

        def test_failsecure(self):
            """Test wrong hostname with fail secure"""
            with TempConfig(MOCKDUO_FAILSECURE) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "whatever", "true"]
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Failsecure Duo login for .*: Couldn't connect to .*: Certificate name validation failed",
                )

        def test_noverify(self):
            """Test wrong hostname with noverify"""
            with TempConfig(MOCKDUO_NOVERIFY) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"]
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Skipped Duo login for 'preauth-allow'.*: preauth-allowed",
                )

    class WithValidCert(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.WithValidCert, self).run(result)

        def test_http_server_abort_errors(self):
            for code in ["400", "402", "403", "404"]:
                for config in [MOCKDUO_CONF, MOCKDUO_FAILSECURE, MOCKDUO_AUTOPUSH]:
                    with TempConfig(config) as temp:
                        result = self.call_binary(
                            ["-d", "-c", temp.name, "-f", code, "true"]
                        )
                        self.assertRegexSomeline(
                            result["stderr"],
                            r"Aborted Duo login for '{code}'.*: HTTP {code}".format(
                                code=code
                            ),
                        )

        def test_http_server_failmode_errors(self):
            for code in ["500", "501", "502", "503", "504"]:
                for config in [MOCKDUO_CONF, MOCKDUO_AUTOPUSH, MOCKDUO_FAILSECURE]:
                    with TempConfig(config) as temp:
                        result = self.call_binary(
                            ["-d", "-c", temp.name, "-f", code, "true"]
                        )
                        self.assertRegexSomeline(
                            result["stderr"],
                            r"{failmode} Duo login for '{code}'.*: HTTP {code}".format(
                                failmode=config.failmode_as_prefix(), code=code
                            ),
                        )

        def test_http_server_invalid_credentials_error(self):
            code = "401"
            for config in [MOCKDUO_CONF, MOCKDUO_AUTOPUSH, MOCKDUO_FAILSECURE]:
                with TempConfig(config) as temp:
                    result = self.call_binary(
                        ["-d", "-c", temp.name, "-f", code, "true"]
                    )
                    self.assertRegexSomeline(
                        result["stderr"],
                        r"{failmode} Duo login for '{code}'.*: Invalid ikey or skey".format(
                            failmode=config.failmode_as_prefix(), code=code
                        ),
                    )

        def test_with_bad_keys(self):
            for config in [MOCKDUO_BADKEYS, MOCKDUO_BADKEYS_FAILSECURE]:
                with TempConfig(config) as temp:
                    result = self.call_binary(
                        ["-d", "-c", temp.name, "-f", "whatever", "true"]
                    )
                    self.assertRegexSomeline(
                        result["stderr"],
                        r"{failmode} Duo login for .*: Invalid ikey or skey".format(
                            failmode=config.failmode_as_prefix()
                        ),
                    )
                    if config.get("failmode", None) == "secure":
                        self.assertEqual(result["returncode"], 1)

    class PreauthStates(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.PreauthStates, self).run(result)

        def check_preauth_state(self, user, message, prefix=None):
            for config in [MOCKDUO_CONF, MOCKDUO_FAILSECURE]:
                with TempConfig(config) as temp:
                    result = self.call_binary(
                        ["-d", "-c", temp.name, "-f", user, "true"]
                    )
                    self.assertRegexSomeline(
                        result["stderr"],
                        r"{prefix} Duo login for '{user}'.*{message}".format(
                            prefix=prefix if prefix else config.failmode_as_prefix(),
                            user=user,
                            message=message,
                        ),
                    )

        def test_preauth_ok_missing_response(self):
            self.check_preauth_state(
                "preauth-ok-missing_response", "JSON missing valid 'response'"
            )

        def test_preauth_fail_missing_response(self):
            self.check_preauth_state(
                "preauth-fail-missing_response", "JSON missing valid 'code'"
            )

        def test_preauth_bad_stat(self):
            self.check_preauth_state("preauth-bad-stat", "")

        def test_preauth_fail(self):
            self.check_preauth_state(
                "preauth-fail", "1000: Pre-authentication failed", prefix="Failed"
            )

        def test_preauth_deny(self):
            self.check_preauth_state("preauth-deny", "preauth-denied", prefix="Aborted")

        def test_preauth_allow(self):
            self.check_preauth_state(
                "preauth-allow", "preauth-allowed", prefix="Skipped"
            )

        def test_preauth_allow_bad_response(self):
            self.check_preauth_state(
                "preauth-allow-bad_response", "JSON missing valid 'status_msg'"
            )

        def test_preauth_allow_retry_after(self):
            start_time = time.time()
            self.check_preauth_state(
                "retry-after-3-preauth-allow", "preauth-allowed", prefix="Skipped"
            )
            execution_time = time.time() - start_time
            # 3.x seconds executed twice
            self.assertGreater(execution_time, 6)

        def test_preauth_allow_retry_after_date(self):
            start_time = time.time()
            self.check_preauth_state(
                "retry-after-date-preauth-allow", "preauth-allowed", prefix="Skipped"
            )
            execution_time = time.time() - start_time
            # 3.x seconds executed twice
            self.assertGreater(execution_time, 6)

        def test_preauth_allow_rate_limited(self):
            start_time = time.time()
            self.check_preauth_state(
                "rate-limited-preauth-allow", "preauth-allowed", prefix="Skipped"
            )
            execution_time = time.time() - start_time
            # 1.x seconds + 2.x seconds executed twice
            self.assertGreater(execution_time, 6)

    class Hosts(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.Hosts, self).run(result)

        def check_host_reporting(self, host):
            with TempConfig(MOCKDUO_CONF) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "-h", host, "true"]
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Skipped Duo login for 'preauth-allow' from {host}: preauth-allowed".format(
                        host=host
                    ),
                )

        def test_host_names(self):
            for host in [
                "1.2.3.4",
                "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:AAA.BBB.CCC.DDD",
                "nowhere",
                '"%s"',
                '"!@#$%^&*()_+<>{}|;\'"',
            ]:
                self.check_host_reporting(host)

    class HTTPProxy(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.HTTPProxy, self).run(result)

        def test_with_no_http_proxy(self):
            with TempConfig(MOCKDUO_CONF) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                    env={},
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Skipped Duo login for 'preauth-allow'.*: preauth-allowed",
                )

        def test_with_broadcast_proxy(self):
            with TempConfig(MOCKDUO_CONF) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                    env={"http_proxy": "0.0.0.0"},
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Skipped Duo login for 'preauth-allow'.*: preauth-allowed",
                )

            with TempConfig(MOCKDUO_PROXY) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                    env={"http_proxy": "0.0.0.0"},
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Failsafe Duo login for .*: Couldn't connect to localhost:4443:.*",
                )

    class GetHostname(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.GetHostname, self).run(result)

        def test_getting_hostname(self):
            config = MOCKDUO_CONF
            with TempConfig(config) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "hostname", "true"],
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Aborted Duo login for 'hostname': correct hostname",
                )
                if config.get("failmode", None) == "secure":
                    self.assertEqual(result["returncode"], 1)

    class FIPS(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.FIPS, self).run(result)

        @unittest.skipIf(
            fips_available() is False, reason="Fips is not supported on this platform"
        )
        def test_fips_login(self):
            with TempConfig(MOCKDUO_FIPS) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                    timeout=10,
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Skipped Duo login for 'preauth-allow'.*: preauth-allowed",
                )

        @unittest.skipIf(
            fips_available() is True, reason="Fips is supported on this platform"
        )
        def test_fips_unavailable(self):
            with TempConfig(MOCKDUO_FIPS) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    "FIPS mode flag specified, but OpenSSL not built with FIPS support. Failing the auth.",
                )

    class PreauthFailures(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.PreauthFailures, self).run(result)

        def test_failmode_preauth_fail(self):
            for config in [MOCKDUO_AUTOPUSH, MOCKDUO_AUTOPUSH_SECURE]:
                with TempConfig(config) as temp:
                    result = self.call_binary(
                        ["-d", "-c", temp.name, "-f", "auth_timeout", "true"],
                    )
                    self.assertRegexSomeline(
                        result["stderr"],
                        r"Error in Duo login for 'auth_timeout': HTTP 500",
                    )

        def test_failopen_report(self):
            with TempConfig(MOCKDUO_CONF) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "failopen", "true"],
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Aborted Duo login for 'failopen': correct failmode",
                )

        def test_failclosed_report(self):
            with TempConfig(MOCKDUO_FAILSECURE) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "failclosed", "true"],
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Aborted Duo login for 'failclosed': correct failmode",
                )

        def test_enroll(self):
            with TempConfig(MOCKDUO_CONF) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "enroll", "true"],
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"User enrollment required",
                )

    class Env(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.Env, self).run(result)

        def test_fallback_and_uid(self):
            with TempConfig(MOCKDUO_FALLBACK) as temp:
                result = self.call_binary(
                    [
                        "-d",
                        "-c",
                        temp.name,
                        "-f",
                        "preauth-allow",
                        "-h",
                        "BADHOST",
                        "true",
                    ],
                    env={
                        "FALLBACK": "1",
                        "UID": "1001",
                    },
                    timeout=15,
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Skipped Duo login for 'preauth-allow'.*: preauth-allowed",
                )

        def test_ssh_connection_host(self):
            with TempConfig(MOCKDUO_CONF) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                    env={
                        "SSH_CONNECTION": "1.2.3.4",
                    },
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r" Skipped Duo login for 'preauth-allow'",
                )

        def test_configuration_with_extra_space(self):
            with TempConfig(MOCKDUO_EXTRA_SPACE) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"]
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Skipped Duo login for 'preauth-allow'.*: preauth-allowed",
                )

    class Interactive(CommonTestCase):
        PROMPT_REGEX = ".* or option \\(1-4\\): $"
        INITIAL_TEXT = [
            ".*Loading config file .*",
        ]
        PROMPT_TEXT = [
            "Duo login for foobar",
            "Choose or lose:",
            "  1. Push 1",
            "  2. Phone 1",
            "  3. SMS 1 (deny)",
            "  4. Phone 2 (deny)",
            "Passcode or option (1-4): ",
        ]

        def remove_header_lines(self, s):
            return s

        def assertOutputEqual(self, output, expected):
            processed_output = [line for line in output.decode().split("\r\n") if line != ""]
            for index, line in enumerate(processed_output):
                if line == expected[index]:
                    continue

                if re.search(expected[index], line):
                    continue

                self.fail(
                    "Line {index} does not match\nExpected: {expected}\nActual: {actual}".format(
                        index=index, expected=expected[index], actual=line
                    )
                )

        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.Interactive, self).run(result)

        def three_failed_inputs(self, config):
            with TempConfig(config) as temp:
                process = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "foobar", "echo", "SUCCESS"],
                )
                self.assertEqual(
                    process.expect(CommonSuites.Interactive.PROMPT_REGEX, timeout=10), 0
                )
                self.assertOutputEqual(
                    self.remove_header_lines(process.match.group(0)),
                    self.INITIAL_TEXT + CommonSuites.Interactive.PROMPT_TEXT,
                )
                process.sendline(b"123456")
                self.assertEqual(
                    process.expect(CommonSuites.Interactive.PROMPT_REGEX, timeout=1), 0
                )
                self.assertOutputEqual(
                    process.match.group(0),
                    [
                        "123456",
                        "Invalid passcode, please try again.",
                        "[4] Failed Duo login for 'foobar'",
                    ]
                    + CommonSuites.Interactive.PROMPT_TEXT,
                )
                process.sendline(b"wefawefgoiagj3rj")
                self.assertEqual(
                    process.expect(CommonSuites.Interactive.PROMPT_REGEX, timeout=1), 0
                )
                self.assertOutputEqual(
                    process.match.group(0),
                    [
                        "wefawefgoiagj3rj",
                        "Invalid passcode, please try again.",
                        "[4] Failed Duo login for 'foobar'",
                    ]
                    + CommonSuites.Interactive.PROMPT_TEXT,
                )

                # apparently solaris only support 256 characters in this prompt
                process.sendline(b"A" * 256)

                self.assertEqual(process.expect(PROMPT), 0)
                self.maxDiff = None
                self.assertOutputEqual(
                    process.before,
                    [
                        "A" * 256,
                        "[3] Error in Duo login for 'foobar'",
                    ],
                )

        def menu_options(self, config):
            with TempConfig(config) as temp:
                process = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "foobar", "true"],
                )
                self.assertEqual(
                    process.expect(CommonSuites.Interactive.PROMPT_REGEX, timeout=10), 0
                )
                self.assertOutputEqual(
                    self.remove_header_lines(process.match.group(0)),
                    self.INITIAL_TEXT + CommonSuites.Interactive.PROMPT_TEXT,
                )
                process.sendline(b"3")
                self.assertEqual(
                    process.expect(CommonSuites.Interactive.PROMPT_REGEX, timeout=5), 0
                )
                self.assertOutputEqual(
                    process.match.group(0),
                    [
                        "3",
                        "New SMS passcodes sent",
                        "[4] Failed Duo login for 'foobar'",
                    ]
                    + CommonSuites.Interactive.PROMPT_TEXT,
                )
                process.sendline(b"4")
                self.assertEqual(
                    process.expect(CommonSuites.Interactive.PROMPT_REGEX, timeout=5), 0
                )
                self.assertOutputEqual(
                    process.match.group(0),
                    [
                        "4",
                        "Dialing XXX-XXX-5678...",
                        "Answered. Press '#' on your phone to log in.",
                        "Authentication timed out.",
                        "[4] Failed Duo login for 'foobar'",
                    ]
                    + CommonSuites.Interactive.PROMPT_TEXT,
                )
                process.sendline(b"1")
                self.assertEqual(process.expect(PROMPT), 0)
                self.assertOutputEqual(
                    process.before,
                    [
                        "1",
                        "Pushed a login request to your phone.",
                        "Success. Logging you in...",
                        "[6] Successful Duo login for 'foobar'",
                    ],
                )

        def menu_success(self, config):
            with TempConfig(config) as temp:
                process = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "foobar", "true"],
                )
                # This is here to prevent race conditions with character entry
                process.expect(CommonSuites.Interactive.PROMPT_REGEX, timeout=10)
                process.sendline(b"2")
                self.assertEqual(process.expect(PROMPT), 0)
                self.assertOutputEqual(
                    process.before,
                    [
                        "2",
                        "Dialing XXX-XXX-1234...",
                        "Answered. Press '#' on your phone to log in.",
                        "Success. Logging you in...",
                        "[6] Successful Duo login for 'foobar'",
                    ],
                )

        def test_three_failed_inputs(self):
            self.three_failed_inputs(MOCKDUO_CONF)

        @unittest.skipIf(
            fips_available() is False, reason="Fips is not supported on this platform"
        )
        def test_fips_three_failed_inputs(self):
            self.three_failed_inputs(MOCKDUO_FIPS)

        def test_menu_options(self):
            self.menu_options(MOCKDUO_CONF)
            self.menu_success(MOCKDUO_CONF)

        @unittest.skipIf(
            fips_available() is False, reason="Fips is not supported on this platform"
        )
        def test_fips_menu_options(self):
            self.menu_options(MOCKDUO_FIPS)
            self.menu_success(MOCKDUO_FIPS)

        def test_autopush_nomenu(self):
            with TempConfig(MOCKDUO_AUTOPUSH) as temp:
                process = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "foobar", "true"],
                )
                self.assertEqual(
                    process.expect("Autopushing login request to phone...", timeout=10),
                    0,
                )

    class InvalidBSON(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.InvalidBSON, self).run(result)

        def test_basic_invalid_json(self):
            with TempConfig(MOCKDUO_CONF) as temp:
                result = self.call_binary(
                    ["-d", "-c", temp.name, "-f", "bad-json", "true"],
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"invalid JSON response",
                )

    class DuoTimeSync(CommonTestCase):
        def run(self, result=None):
            with MockDuo(NORMAL_CERT):
                return super(CommonSuites.DuoTimeSync, self).run(result)

        def test_time_sync_success(self):
            """Test successful time sync with /auth/v2/ping"""
            with TempConfig(MOCKDUO_CONF) as temp:
                result = self.call_binary([
                    "-d", "-c", temp.name, "-f", "foobar", "true"
                ])
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Successful Duo login for 'foobar'",
                )
                # Optionally, check for log message about time sync if available

        def test_time_sync_with_skew(self):
            """Test time sync with server time skew (offset is used)"""
            with TempConfig(MOCKDUO_CONF) as temp:
                # Set the server time skew to +400 seconds permanently
                params = {"skew": 400, "mode": "permanent"}
                query = urllib.parse.urlencode(params)
                url = f"https://localhost:4443/mockduo/set-skew?{query}"
                context = ssl._create_unverified_context()
                with urllib.request.urlopen(url, context=context) as response:
                    response.read()
                result = self.call_binary(["-d", "-c", temp.name, "-f", "foobar", "true"])
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Successful Duo login for 'foobar'",
                )
                # Reset skew after test
                params = {"skew": 0, "mode": "permanent"}
                query = urllib.parse.urlencode(params)
                url = f"https://localhost:4443/mockduo/set-skew?{query}"
                with urllib.request.urlopen(url, context=context) as response:
                    response.read()

        def test_time_sync_with_skew_failed(self):
            """Test time sync with server time skew (offset is used)"""
            with TempConfig(MOCKDUO_CONF) as temp:
                # Set skew to 400 for the next request only (ping)
                params = {"skew": 400, "mode": "once"}
                query = urllib.parse.urlencode(params)
                url = f"https://localhost:4443/mockduo/set-skew?{query}"
                context = ssl._create_unverified_context()
                with urllib.request.urlopen(url, context=context) as response:
                    response.read()
                # The client will sync to +400, but the next auth will have 0 skew
                result = self.call_binary(["-d", "-c", temp.name, "-f", "foobar", "true"])
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Failsafe Duo login for 'foobar': Invalid ikey or skey",
                )

    class VerifiedPush(CommonTestCase):
            def run(self, result=None):
                with MockDuo(NORMAL_CERT):
                    return super().run(result)

            def test_verified_push_success(self):
                """Test successful login with verified push username"""
                with TempConfig(MOCKDUO_VERIFIED_PUSH) as temp:
                    result = self.call_binary([
                        "-d", "-c", temp.name, "-f", "client_supports_verified_push", "true"
                    ])
                    self.assertRegexSomeline(
                        result["stderr"],
                        r"Successful Duo login for 'client_supports_verified_push'",
                    )

            def test_verified_push_ignored(self):
                """Test successful login with verified push ignored username"""
                with TempConfig(MOCKDUO_VERIFIED_PUSH) as temp:
                    result = self.call_binary([
                        "-d", "-c", temp.name, "-f", "client_supports_verified_push-ignored", "true"
                    ])
                    self.assertRegexSomeline(
                        result["stderr"],
                        r"Successful Duo login for 'client_supports_verified_push-ignored'",
                    )