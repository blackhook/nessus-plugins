#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0127. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154452);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2020-12723");
  script_xref(name:"IAVA", value:"2020-A-0268");

  script_name(english:"NewStart CGSL MAIN 6.02 : perl Vulnerability (NS-SA-2021-0127)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has perl packages installed that are affected by a
vulnerability:

  - regcomp.c in Perl before 5.30.3 allows a buffer overflow via a crafted regular expression because of
    recursive S_study_chunk calls. (CVE-2020-12723)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0127");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12723");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL perl packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12723");

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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'perl-5.26.3-417.el8_3',
    'perl-Attribute-Handlers-0.99-417.el8_3',
    'perl-Devel-Peek-1.26-417.el8_3',
    'perl-Devel-Peek-debuginfo-1.26-417.el8_3',
    'perl-Devel-SelfStubber-1.06-417.el8_3',
    'perl-Errno-1.28-417.el8_3',
    'perl-ExtUtils-Embed-1.34-417.el8_3',
    'perl-ExtUtils-Miniperl-1.06-417.el8_3',
    'perl-IO-1.38-417.el8_3',
    'perl-IO-Zlib-1.10-417.el8_3',
    'perl-IO-debuginfo-1.38-417.el8_3',
    'perl-Locale-Maketext-Simple-0.21-417.el8_3',
    'perl-Math-Complex-1.59-417.el8_3',
    'perl-Memoize-1.03-417.el8_3',
    'perl-Module-Loaded-0.08-417.el8_3',
    'perl-Net-Ping-2.55-417.el8_3',
    'perl-Pod-Html-1.22.02-417.el8_3',
    'perl-SelfLoader-1.23-417.el8_3',
    'perl-Test-1.30-417.el8_3',
    'perl-Time-Piece-1.31-417.el8_3',
    'perl-Time-Piece-debuginfo-1.31-417.el8_3',
    'perl-debuginfo-5.26.3-417.el8_3',
    'perl-debugsource-5.26.3-417.el8_3',
    'perl-devel-5.26.3-417.el8_3',
    'perl-interpreter-5.26.3-417.el8_3',
    'perl-interpreter-debuginfo-5.26.3-417.el8_3',
    'perl-libnetcfg-5.26.3-417.el8_3',
    'perl-libs-5.26.3-417.el8_3',
    'perl-libs-debuginfo-5.26.3-417.el8_3',
    'perl-macros-5.26.3-417.el8_3',
    'perl-open-1.11-417.el8_3',
    'perl-tests-5.26.3-417.el8_3',
    'perl-utils-5.26.3-417.el8_3'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
