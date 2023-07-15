#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0043. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127221);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-16395");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : ruby Vulnerability (NS-SA-2019-0043)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has ruby packages installed that are affected by a
vulnerability:

  - An issue was discovered in the OpenSSL library in Ruby
    before 2.3.8, 2.4.x before 2.4.5, 2.5.x before 2.5.2,
    and 2.6.x before 2.6.0-preview3. When two
    OpenSSL::X509::Name objects are compared using ==,
    depending on the ordering, non-equal objects may return
    true. When the first argument is one character longer
    than the second, or the second argument contains a
    character that is one less than a character in the same
    position of the first argument, the result of == will be
    true. This could be leveraged to create an illegitimate
    certificate that may be accepted as legitimate and then
    used in signing or encryption operations.
    (CVE-2018-16395)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0043");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ruby packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/16");
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
    "ruby-2.0.0.648-34.el7_6",
    "ruby-debuginfo-2.0.0.648-34.el7_6",
    "ruby-devel-2.0.0.648-34.el7_6",
    "ruby-doc-2.0.0.648-34.el7_6",
    "ruby-irb-2.0.0.648-34.el7_6",
    "ruby-libs-2.0.0.648-34.el7_6",
    "ruby-tcltk-2.0.0.648-34.el7_6",
    "rubygem-bigdecimal-1.2.0-34.el7_6",
    "rubygem-io-console-0.4.2-34.el7_6",
    "rubygem-json-1.7.7-34.el7_6",
    "rubygem-minitest-4.3.2-34.el7_6",
    "rubygem-psych-2.0.0-34.el7_6",
    "rubygem-rake-0.9.6-34.el7_6",
    "rubygem-rdoc-4.0.0-34.el7_6",
    "rubygems-2.0.14.1-34.el7_6",
    "rubygems-devel-2.0.14.1-34.el7_6"
  ],
  "CGSL MAIN 5.04": [
    "ruby-2.0.0.648-34.el7_6",
    "ruby-debuginfo-2.0.0.648-34.el7_6",
    "ruby-devel-2.0.0.648-34.el7_6",
    "ruby-doc-2.0.0.648-34.el7_6",
    "ruby-irb-2.0.0.648-34.el7_6",
    "ruby-libs-2.0.0.648-34.el7_6",
    "ruby-tcltk-2.0.0.648-34.el7_6",
    "rubygem-bigdecimal-1.2.0-34.el7_6",
    "rubygem-io-console-0.4.2-34.el7_6",
    "rubygem-json-1.7.7-34.el7_6",
    "rubygem-minitest-4.3.2-34.el7_6",
    "rubygem-psych-2.0.0-34.el7_6",
    "rubygem-rake-0.9.6-34.el7_6",
    "rubygem-rdoc-4.0.0-34.el7_6",
    "rubygems-2.0.14.1-34.el7_6",
    "rubygems-devel-2.0.14.1-34.el7_6"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
