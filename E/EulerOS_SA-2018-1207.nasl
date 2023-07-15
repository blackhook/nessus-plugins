#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110871);
  script_version("1.44");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-1000075",
    "CVE-2018-1000076",
    "CVE-2018-6914",
    "CVE-2018-8777",
    "CVE-2018-8778",
    "CVE-2018-8779",
    "CVE-2018-8780"
  );

  script_name(english:"EulerOS 2.0 SP3 : ruby (EulerOS-SA-2018-1207)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ruby packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - It was found that the tmpdir and tempfile modules did
    not sanitize their file name argument. An attacker with
    control over the name could create temporary files and
    directories outside of the dedicated
    directory.(CVE-2018-6914)

  - A integer underflow was found in the way String#unpack
    decodes the unpacking format. An attacker, able to
    control the unpack format, could use this flaw to
    disclose arbitrary parts of the application's
    memory.(CVE-2018-8778)

  - It was found that the UNIXSocket::open and
    UNIXServer::open ruby methods did not handle the NULL
    byte properly. An attacker, able to inject NULL bytes
    in the socket path, could possibly trigger an
    unspecified behavior of the ruby script.(CVE-2018-8779)

  - It was found that the methods from the Dir class did
    not properly handle strings containing the NULL byte.
    An attacker, able to inject NULL bytes in a path, could
    possibly trigger an unspecified behavior of the ruby
    script.(CVE-2018-8780)

  - It was found that WEBrick could be forced to use an
    excessive amount of memory during the processing of
    HTTP requests, leading to a Denial of Service. An
    attacker could use this flaw to send huge requests to a
    WEBrick application, resulting in the server running
    out of memory.(CVE-2018-8777)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a infinite loop
    caused by negative size vulnerability in ruby gem
    package tar header that can result in a negative size
    could cause an infinite loop.. This vulnerability
    appears to have been fixed in 2.7.6.(CVE-2018-1000075)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Improper
    Verification of Cryptographic Signature vulnerability
    in package.rb that can result in a mis-signed gem could
    be installed, as the tarball would contain multiple gem
    signatures.. This vulnerability appears to have been
    fixed in 2.7.6.(CVE-2018-1000076)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1207
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ada4070");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ruby-2.0.0.648-33.h10",
        "ruby-irb-2.0.0.648-33.h10",
        "ruby-libs-2.0.0.648-33.h10"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
