##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0110. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143995);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id(
    "CVE-2018-21009",
    "CVE-2019-9959",
    "CVE-2019-10871",
    "CVE-2019-12293"
  );
  script_bugtraq_id(107862, 108457, 109342);

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : poppler Multiple Vulnerabilities (NS-SA-2020-0110)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has poppler packages installed that are affected
by multiple vulnerabilities:

  - An issue was discovered in Poppler 0.74.0. There is a heap-based buffer over-read in the function
    PSOutputDev::checkPageSlice at PSOutputDev.cc. (CVE-2019-10871)

  - The JPXStream::init function in Poppler 0.78.0 and earlier doesn't check for negative values of stream
    length, leading to an Integer Overflow, thereby making it possible to allocate a large memory chunk on the
    heap, with a size controlled by an attacker, as demonstrated by pdftocairo. (CVE-2019-9959)

  - In Poppler through 0.76.1, there is a heap-based buffer over-read in JPXStream::init in JPEG2000Stream.cc
    via data with inconsistent heights or widths. (CVE-2019-12293)

  - Poppler before 0.66.0 has an integer overflow in Parser::makeStream in Parser.cc. (CVE-2018-21009)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0110");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL poppler packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12293");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.05': [
    'poppler-0.26.5-42.el7',
    'poppler-cpp-0.26.5-42.el7',
    'poppler-cpp-devel-0.26.5-42.el7',
    'poppler-debuginfo-0.26.5-42.el7',
    'poppler-demos-0.26.5-42.el7',
    'poppler-devel-0.26.5-42.el7',
    'poppler-glib-0.26.5-42.el7',
    'poppler-glib-devel-0.26.5-42.el7',
    'poppler-qt-0.26.5-42.el7',
    'poppler-qt-devel-0.26.5-42.el7',
    'poppler-utils-0.26.5-42.el7'
  ],
  'CGSL MAIN 5.05': [
    'poppler-0.26.5-42.el7',
    'poppler-cpp-0.26.5-42.el7',
    'poppler-cpp-devel-0.26.5-42.el7',
    'poppler-debuginfo-0.26.5-42.el7',
    'poppler-demos-0.26.5-42.el7',
    'poppler-devel-0.26.5-42.el7',
    'poppler-glib-0.26.5-42.el7',
    'poppler-glib-devel-0.26.5-42.el7',
    'poppler-qt-0.26.5-42.el7',
    'poppler-qt-devel-0.26.5-42.el7',
    'poppler-utils-0.26.5-42.el7'
  ]
};
pkg_list = pkgs[release];

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'poppler');
}
