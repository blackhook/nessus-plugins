#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0054. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127242);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-18311");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : perl Vulnerability (NS-SA-2019-0054)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has perl packages installed that are affected by a
vulnerability:

  - Perl before 5.26.3 and 5.28.x before 5.28.1 has a buffer
    overflow via a crafted regular expression that triggers
    invalid write operations. (CVE-2018-18311)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0054");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL perl packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18311");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "perl-5.16.3-294.el7_6",
    "perl-CPAN-1.9800-294.el7_6",
    "perl-ExtUtils-CBuilder-0.28.2.6-294.el7_6",
    "perl-ExtUtils-Embed-1.30-294.el7_6",
    "perl-ExtUtils-Install-1.58-294.el7_6",
    "perl-IO-Zlib-1.10-294.el7_6",
    "perl-Locale-Maketext-Simple-0.21-294.el7_6",
    "perl-Module-CoreList-2.76.02-294.el7_6",
    "perl-Module-Loaded-0.08-294.el7_6",
    "perl-Object-Accessor-0.42-294.el7_6",
    "perl-Package-Constants-0.02-294.el7_6",
    "perl-Pod-Escapes-1.04-294.el7_6",
    "perl-Time-Piece-1.20.1-294.el7_6",
    "perl-core-5.16.3-294.el7_6",
    "perl-debuginfo-5.16.3-294.el7_6",
    "perl-devel-5.16.3-294.el7_6",
    "perl-libs-5.16.3-294.el7_6",
    "perl-macros-5.16.3-294.el7_6",
    "perl-tests-5.16.3-294.el7_6"
  ],
  "CGSL MAIN 5.04": [
    "perl-5.16.3-294.el7_6",
    "perl-CPAN-1.9800-294.el7_6",
    "perl-ExtUtils-CBuilder-0.28.2.6-294.el7_6",
    "perl-ExtUtils-Embed-1.30-294.el7_6",
    "perl-ExtUtils-Install-1.58-294.el7_6",
    "perl-IO-Zlib-1.10-294.el7_6",
    "perl-Locale-Maketext-Simple-0.21-294.el7_6",
    "perl-Module-CoreList-2.76.02-294.el7_6",
    "perl-Module-Loaded-0.08-294.el7_6",
    "perl-Object-Accessor-0.42-294.el7_6",
    "perl-Package-Constants-0.02-294.el7_6",
    "perl-Pod-Escapes-1.04-294.el7_6",
    "perl-Time-Piece-1.20.1-294.el7_6",
    "perl-core-5.16.3-294.el7_6",
    "perl-debuginfo-5.16.3-294.el7_6",
    "perl-devel-5.16.3-294.el7_6",
    "perl-libs-5.16.3-294.el7_6",
    "perl-macros-5.16.3-294.el7_6",
    "perl-tests-5.16.3-294.el7_6"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}