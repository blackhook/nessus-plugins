#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0085. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167455);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/14");

  script_cve_id(
    "CVE-2016-10228",
    "CVE-2019-25013",
    "CVE-2020-27618",
    "CVE-2021-3326",
    "CVE-2021-3999",
    "CVE-2021-27645",
    "CVE-2021-33574",
    "CVE-2022-23218",
    "CVE-2022-23219"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : glibc Multiple Vulnerabilities (NS-SA-2022-0085)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has glibc packages installed that are affected by multiple
vulnerabilities:

  - The iconv program in the GNU C Library (aka glibc or libc6) 2.31 and earlier, when invoked with multiple
    suffixes in the destination encoding (TRANSLATE or IGNORE) along with the -c option, enters an infinite
    loop when processing invalid multi-byte input sequences, leading to a denial of service. (CVE-2016-10228)

  - The iconv feature in the GNU C Library (aka glibc or libc6) through 2.32, when processing invalid multi-
    byte input sequences in the EUC-KR encoding, may have a buffer over-read. (CVE-2019-25013)

  - The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid
    multi-byte input sequences in IBM1364, IBM1371, IBM1388, IBM1390, and IBM1399 encodings, fails to advance
    the input state, which could lead to an infinite loop in applications, resulting in a denial of service, a
    different vulnerability from CVE-2016-10228. (CVE-2020-27618)

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
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0085");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2016-10228");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25013");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-27618");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-27645");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3326");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-33574");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3999");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-23218");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-23219");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:compat-libpthread-nonshared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss_db");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'compat-libpthread-nonshared-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-all-langpacks-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-common-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-devel-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-headers-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-langpack-en-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-langpack-zh-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-locale-source-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-minimal-langpack-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'glibc-static-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'libnsl-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'nscd-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76',
    'nss_db-2.28-164.el8_5.3.cgslv6_2.1.g263e1a76'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc');
}
