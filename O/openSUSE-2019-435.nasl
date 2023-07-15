#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-435.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123190);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1000300", "CVE-2018-1000301");

  script_name(english:"openSUSE Security Update : curl (openSUSE-2019-435)");
  script_summary(english:"Check for the openSUSE-2019-435 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for curl to version 7.60.0 fixes the following issues :

These security issues were fixed :

  - CVE-2018-1000300: Prevent heap-based buffer overflow
    when closing down an FTP connection with very long
    server command replies (bsc#1092094).

  - CVE-2018-1000301: Prevent buffer over-read that could
    have cause reading data beyond the end of a heap based
    buffer used to store downloaded RTSP content
    (bsc#1092098).

These non-security issues were fixed :

  - Add CURLOPT_HAPROXYPROTOCOL, support for the HAProxy
    PROXY protocol

  - Add --haproxy-protocol for the command line tool

  - Add CURLOPT_DNS_SHUFFLE_ADDRESSES, shuffle returned IP
    addresses 

  - FTP: fix typo in recursive callback detection for
    seeking

  - test1208: marked flaky

  - HTTP: make header-less responses still count correct
    body size

  - user-agent.d:: mention --proxy-header as well

- http2: fixes typo

  - cleanup: misc typos in strings and comments

  - rate-limit: use three second window to better handle
    high speeds

  - examples/hiperfifo.c: improved

  - pause: when changing pause state, update socket state

  - curl_version_info.3: fix ssl_version description

  - add_handle/easy_perform: clear errorbuffer on start if
    set

  - cmake: add support for brotli

  - parsedate: support UT timezone

  - vauth/ntlm.h: fix the #ifdef header guard

  - lib/curl_path.h: added #ifdef header guard

  - vauth/cleartext: fix integer overflow check

  - CURLINFO_COOKIELIST.3: made the example not leak memory

  - cookie.d: mention that '-' as filename means stdin

  - CURLINFO_SSL_VERIFYRESULT.3: fixed the example

- http2: read pending frames
  (including GOAWAY) in connection-check

  - timeval: remove compilation warning by casting

  - cmake: avoid warn-as-error during config checks

  - travis-ci: enable -Werror for CMake builds

  - openldap: fix for NULL return from
    ldap_get_attribute_ber()

  - threaded resolver: track resolver time and set suitable
    timeout values

  - cmake: Add advapi32 as explicit link library for win32

  - docs: fix CURLINFO_*_T examples use of
    CURL_FORMAT_CURL_OFF_T

  - test1148: set a fixed locale for the test

  - cookies: when reading from a file, only remove_expired
    once

  - cookie: store cookies per top-level-domain-specific hash
    table

  - openssl: RESTORED verify locations when verifypeer==0

  - file: restore old behavior for file:////foo/bar URLs

  - FTP: allow PASV on IPv6 connections when a proxy is
    being used

  - build-openssl.bat: allow custom paths for VS and perl

  - winbuild: make the clean target work without build-type

  - build-openssl.bat: Refer to VS2017 as VC14.1 instead of
    VC15

  - curl: retry on FTP 4xx, ignore other protocols

  - configure: detect (and use) sa_family_t

  - examples/sftpuploadresume: Fix Windows large file seek

  - build: cleanup to fix clang warnings/errors

  - winbuild: updated the documentation

  - lib: silence null-dereference warnings

  - travis: bump to clang 6 and gcc 7

  - travis: build libpsl and make builds use it

  - proxy: show getenv proxy use in verbose output

  - duphandle: make sure CURLOPT_RESOLVE is duplicated

  - all: Refactor malloc+memset to use calloc

  - checksrc: Fix typo

  - system.h: Add sparcv8plus to oracle/sunpro 32-bit
    detection

  - vauth: Fix typo

  - ssh: show libSSH2 error code when closing fails

  - test1148: tolerate progress updates better

  - urldata: make service names unconditional

  - configure: keep LD_LIBRARY_PATH changes local

  - ntlm_sspi: fix authentication using Credential Manager

  - schannel: add client certificate authentication

  - winbuild: Support custom devel paths for each dependency

  - schannel: add support for CURLOPT_CAINFO

- http2: handle on_begin_headers() called more than once

  - openssl: support OpenSSL 1.1.1 verbose-mode trace
    messages

  - openssl: fix subjectAltName check on non-ASCII platforms

- http2: avoid strstr() on data not zero terminated

- http2: clear the 'drain counter' when a stream is closed

- http2: handle GOAWAY properly

  - tool_help: clarify --max-time unit of time is seconds

  - curl.1: clarify that options and URLs can be mixed

- http2: convert an assert to run-time check

  - curl_global_sslset: always provide available backends

  - ftplistparser: keep state between invokes

  - Curl_memchr: zero length input can't match

  - examples/sftpuploadresume: typecast fseek argument to
    long

  - examples/http2-upload: expand buffer to avoid silly
    warning

  - ctype: restore character classification for non-ASCII
    platforms

  - mime: avoid NULL pointer dereference risk

  - cookies: ensure that we have cookies before writing jar

  - os400.c: fix checksrc warnings

  - configure: provide --with-wolfssl as an alias for
    --with-cyassl

  - cyassl: adapt to libraries without TLS 1.0 support
    built-in

- http2: get rid of another strstr

  - checksrc: force indentation of lines after an else

  - cookies: remove unused macro

  - CURLINFO_PROTOCOL.3: mention the existing defined names

  - tests: provide 'manual' as a feature to optionally
    require

  - travis: enable libssh2 on both macos and Linux

  - CURLOPT_URL.3: added ENCODING section

  - wolfssl: Fix non-blocking connect

  - vtls: don't define MD5_DIGEST_LENGTH for wolfssl

  - docs: remove extraneous commas in man pages

  - URL: fix ASCII dependency in strcpy_url and strlen_url

  - ssh-libssh.c: fix left shift compiler warning

  - configure: only check for CA bundle for file-using SSL
    backends

  - travis: add an mbedtls build

- http: don't set the 'rewind' flag when not uploading anything

  - configure: put CURLDEBUG and DEBUGBUILD in
    lib/curl_config.h

  - transfer: don't unset writesockfd on setup of
    multiplexed conns

  - vtls: use unified 'supports' bitfield member in backends

  - URLs: fix one more http url

  - travis: add a build using WolfSSL

  - openssl: change FILE ops to BIO ops

  - travis: add build using NSS

  - smb: reject negative file sizes

  - cookies: accept parameter names as cookie name

- http2: getsock fix for uploads

  - all over: fixed format specifiers

- http2: use the correct function pointer typedef"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092098"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"curl-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"curl-debuginfo-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"curl-debugsource-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"curl-mini-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"curl-mini-debuginfo-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"curl-mini-debugsource-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcurl-devel-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcurl-mini-devel-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcurl4-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcurl4-debuginfo-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcurl4-mini-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcurl4-mini-debuginfo-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcurl-devel-32bit-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcurl4-32bit-7.60.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcurl4-32bit-debuginfo-7.60.0-lp150.2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl-mini / curl-mini-debuginfo / curl-mini-debugsource / etc");
}
