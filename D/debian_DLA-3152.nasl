#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3152. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166426);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/23");

  script_cve_id(
    "CVE-2016-10228",
    "CVE-2019-19126",
    "CVE-2019-25013",
    "CVE-2020-1752",
    "CVE-2020-6096",
    "CVE-2020-10029",
    "CVE-2020-27618",
    "CVE-2021-3326",
    "CVE-2021-3999",
    "CVE-2021-27645",
    "CVE-2021-33574",
    "CVE-2021-35942",
    "CVE-2022-23218",
    "CVE-2022-23219"
  );

  script_name(english:"Debian DLA-3152-1 : glibc - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3152 advisory.

  - The iconv program in the GNU C Library (aka glibc or libc6) 2.31 and earlier, when invoked with multiple
    suffixes in the destination encoding (TRANSLATE or IGNORE) along with the -c option, enters an infinite
    loop when processing invalid multi-byte input sequences, leading to a denial of service. (CVE-2016-10228)

  - On the x86-64 architecture, the GNU C Library (aka glibc) before 2.31 fails to ignore the
    LD_PREFER_MAP_32BIT_EXEC environment variable during program execution after a security transition,
    allowing local attackers to restrict the possible mapping addresses for loaded libraries and thus bypass
    ASLR for a setuid program. (CVE-2019-19126)

  - The iconv feature in the GNU C Library (aka glibc or libc6) through 2.32, when processing invalid multi-
    byte input sequences in the EUC-KR encoding, may have a buffer over-read. (CVE-2019-25013)

  - The GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range
    reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when
    passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to
    sysdeps/ieee754/ldbl-96/e_rem_pio2l.c. (CVE-2020-10029)

  - A use-after-free vulnerability introduced in glibc upstream version 2.14 was found in the way the tilde
    expansion was carried out. Directory paths containing an initial tilde followed by a valid username were
    affected by this issue. A local attacker could exploit this flaw by creating a specially crafted path
    that, when processed by the glob function, would potentially lead to arbitrary code execution. This was
    fixed in version 2.32. (CVE-2020-1752)

  - The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid
    multi-byte input sequences in IBM1364, IBM1371, IBM1388, IBM1390, and IBM1399 encodings, fails to advance
    the input state, which could lead to an infinite loop in applications, resulting in a denial of service, a
    different vulnerability from CVE-2016-10228. (CVE-2020-27618)

  - An exploitable signed comparison vulnerability exists in the ARMv7 memcpy() implementation of GNU glibc
    2.30.9000. Calling memcpy() (on ARMv7 targets that utilize the GNU glibc implementation) with a negative
    value for the 'num' parameter results in a signed comparison vulnerability. If an attacker underflows the
    'num' parameter to memcpy(), this vulnerability could lead to undefined behavior such as writing to out-
    of-bounds memory and potentially remote code execution. Furthermore, this memcpy() implementation allows
    for program execution to continue in scenarios where a segmentation fault or crash should have occurred.
    The dangers occur in that subsequent execution and iterations of this code will be executed with this
    corrupted data. (CVE-2020-6096)

  - The nameserver caching daemon (nscd) in the GNU C Library (aka glibc or libc6) 2.29 through 2.33, when
    processing a request for netgroup lookup, may crash due to a double-free, potentially resulting in
    degraded service or Denial of Service on the local system. This is related to netgroupcache.c.
    (CVE-2021-27645)

  - The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid
    input sequences in the ISO-2022-JP-3 encoding, fails an assertion in the code path and aborts the program,
    potentially resulting in a denial of service. (CVE-2021-3326)

  - The mq_notify function in the GNU C Library (aka glibc) versions 2.32 and 2.33 has a use-after-free. It
    may use the notification thread attributes object (passed through its struct sigevent parameter) after it
    has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified
    other impact. (CVE-2021-33574)

  - The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in
    parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in
    a denial of service or disclosure of information. This occurs because atoi was used but strtoul should
    have been used to ensure correct calculations. (CVE-2021-35942)

  - A flaw was found in glibc. An off-by-one buffer overflow and underflow in getcwd() may lead to memory
    corruption when the size of the buffer is exactly 1. A local attacker who can control the input buffer and
    size passed to getcwd() in a setuid program could use this flaw to potentially execute arbitrary code and
    escalate their privileges on the system. (CVE-2021-3999)

  - The deprecated compatibility function svcunix_create in the sunrpc module of the GNU C Library (aka glibc)
    through 2.34 copies its path argument on the stack without validating its length, which may result in a
    buffer overflow, potentially resulting in a denial of service or (if an application is not built with a
    stack protector enabled) arbitrary code execution. (CVE-2022-23218)

  - The deprecated compatibility function clnt_create in the sunrpc module of the GNU C Library (aka glibc)
    through 2.34 copies its hostname argument on the stack without validating its length, which may result in
    a buffer overflow, potentially resulting in a denial of service or (if an application is not built with a
    stack protector enabled) arbitrary code execution. (CVE-2022-23219)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=856503");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/glibc");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3152");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-10228");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-19126");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-25013");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10029");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1752");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27618");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-6096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-27645");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3326");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33574");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-35942");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3999");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23219");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/glibc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the glibc packages.

For Debian 10 buster, these problems have been fixed in version 2.28-10+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multiarch-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'glibc-doc', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'glibc-source', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc-bin', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc-dev-bin', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc-l10n', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-amd64', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-dbg', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-dev', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-dev-amd64', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-dev-i386', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-dev-x32', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-i386', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-pic', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-x32', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'libc6-xen', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'locales', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'locales-all', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'multiarch-support', 'reference': '2.28-10+deb10u2'},
    {'release': '10.0', 'prefix': 'nscd', 'reference': '2.28-10+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-doc / glibc-source / libc-bin / libc-dev-bin / libc-l10n / libc6 / etc');
}
