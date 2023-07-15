#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0134. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154556);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878");
  script_xref(name:"IAVA", value:"2020-A-0268");
  script_xref(name:"IAVA", value:"2021-A-0030");
  script_xref(name:"IAVA", value:"2021-A-0328");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL MAIN 6.02 : perl Multiple Vulnerabilities (NS-SA-2021-0134)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has perl packages installed that are affected by multiple
vulnerabilities:

  - Perl before 5.30.3 on 32-bit platforms allows a heap-based buffer overflow because nested regular
    expression quantifiers have an integer overflow. (CVE-2020-10543)

  - Perl before 5.30.3 has an integer overflow related to mishandling of a PL_regkind[OP(n)] == NOTHING
    situation. A crafted regular expression could lead to malformed bytecode with a possibility of instruction
    injection. (CVE-2020-10878)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0134");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-10543");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-10878");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL perl packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Devel-Peek-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-IO-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Net-Ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Time-Piece-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-interpreter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'perl-5.26.3-419.el8',
    'perl-Attribute-Handlers-0.99-419.el8',
    'perl-Devel-Peek-1.26-419.el8',
    'perl-Devel-Peek-debuginfo-1.26-419.el8',
    'perl-Devel-SelfStubber-1.06-419.el8',
    'perl-Errno-1.28-419.el8',
    'perl-ExtUtils-Embed-1.34-419.el8',
    'perl-ExtUtils-Miniperl-1.06-419.el8',
    'perl-IO-1.38-419.el8',
    'perl-IO-Zlib-1.10-419.el8',
    'perl-IO-debuginfo-1.38-419.el8',
    'perl-Locale-Maketext-Simple-0.21-419.el8',
    'perl-Math-Complex-1.59-419.el8',
    'perl-Memoize-1.03-419.el8',
    'perl-Module-Loaded-0.08-419.el8',
    'perl-Net-Ping-2.55-419.el8',
    'perl-Pod-Html-1.22.02-419.el8',
    'perl-SelfLoader-1.23-419.el8',
    'perl-Test-1.30-419.el8',
    'perl-Time-Piece-1.31-419.el8',
    'perl-Time-Piece-debuginfo-1.31-419.el8',
    'perl-debuginfo-5.26.3-419.el8',
    'perl-debugsource-5.26.3-419.el8',
    'perl-devel-5.26.3-419.el8',
    'perl-interpreter-5.26.3-419.el8',
    'perl-interpreter-debuginfo-5.26.3-419.el8',
    'perl-libnetcfg-5.26.3-419.el8',
    'perl-libs-5.26.3-419.el8',
    'perl-libs-debuginfo-5.26.3-419.el8',
    'perl-macros-5.26.3-419.el8',
    'perl-open-1.11-419.el8',
    'perl-tests-5.26.3-419.el8',
    'perl-utils-5.26.3-419.el8'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl');
}
