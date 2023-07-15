#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142322);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-17742",
    "CVE-2018-1000073",
    "CVE-2018-1000074",
    "CVE-2018-1000077",
    "CVE-2018-1000078",
    "CVE-2018-1000079",
    "CVE-2019-16201"
  );

  script_name(english:"EulerOS 2.0 SP2 : ruby (EulerOS-SA-2020-2395)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ruby packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - WEBrick::HTTPAuth::DigestAuth in Ruby through 2.4.7,
    2.5.x through 2.5.6, and 2.6.x through 2.6.4 has a
    regular expression Denial of Service cause by
    looping/backtracking. A victim must expose a WEBrick
    server that uses DigestAuth to the Internet or a
    untrusted network.(CVE-2019-16201)

  - Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before
    2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1 allows an
    HTTP Response Splitting attack. An attacker can inject
    a crafted key and value into an HTTP response for the
    HTTP server of WEBrick.(CVE-2017-17742)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Directory
    Traversal vulnerability in install_location function of
    package.rb that can result in path traversal when
    writing to a symlinked basedir outside of the root.
    This vulnerability appears to have been fixed in
    2.7.6.(CVE-2018-1000073)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a
    Deserialization of Untrusted Data vulnerability in
    owner command that can result in code execution. This
    attack appear to be exploitable via victim must run the
    `gem owner` command on a gem with a specially crafted
    YAML file.(CVE-2018-1000074)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Improper Input
    Validation vulnerability in ruby gems specification
    homepage attribute that can result in a malicious gem
    could set an invalid homepage URL.(CVE-2018-1000077)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Cross Site
    Scripting (XSS) vulnerability in gem server display of
    homepage attribute that can result in XSS. This attack
    appear to be exploitable via the victim must browse to
    a malicious gem on a vulnerable gem
    server.(CVE-2018-1000078)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Directory
    Traversal vulnerability in gem installation that can
    result in the gem could write to arbitrary filesystem
    locations during installation. This attack appear to be
    exploitable via the victim must install a malicious
    gem.(CVE-2018-1000079)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2395
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb9b90dc");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000074");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ruby-2.0.0.648-33.h19",
        "ruby-irb-2.0.0.648-33.h19",
        "ruby-libs-2.0.0.648-33.h19"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
