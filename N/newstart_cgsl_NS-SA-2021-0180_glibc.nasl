#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0180. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154460);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2019-19126",
    "CVE-2019-25013",
    "CVE-2020-10029",
    "CVE-2020-29573"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : glibc Multiple Vulnerabilities (NS-SA-2021-0180)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has glibc packages installed that are affected by
multiple vulnerabilities:

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

  - sysdeps/i386/ldbl2mpn.c in the GNU C Library (aka glibc or libc6) before 2.23 on x86 targets has a stack-
    based buffer overflow if the input to any of the printf family of functions is an 80-bit long double with
    a non-canonical bit pattern, as seen when passing a \x00\x04\x00\x00\x00\x00\x00\x00\x00\x04 value to
    sprintf. NOTE: the issue does not affect glibc by default in 2016 or later (i.e., 2.23 or later) because
    of commits made in 2015 for inlining of C99 math functions through use of GCC built-ins. In other words,
    the reference to 2.23 is intentional despite the mention of Fixed for glibc 2.33 in the 26649 reference.
    (CVE-2020-29573)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0180");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-19126");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-25013");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-10029");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-29573");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'glibc-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-common-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-debuginfo-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-debuginfo-common-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-devel-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-headers-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-i18n-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-iconv-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-lang-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-locale-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-static-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-tools-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'glibc-utils-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite',
    'nscd-2.17-322.el7_9.cgslv5_5.0.7.g84f7681.lite'
  ],
  'CGSL MAIN 5.05': [
    'glibc-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08',
    'glibc-common-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08',
    'glibc-debuginfo-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08',
    'glibc-debuginfo-common-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08',
    'glibc-devel-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08',
    'glibc-headers-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08',
    'glibc-static-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08',
    'glibc-utils-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08',
    'nscd-2.17-322.el7_9.cgslv5_5.0.2.gdcf6e08'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
