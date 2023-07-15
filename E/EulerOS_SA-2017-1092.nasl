#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100687);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-10195",
    "CVE-2016-10196",
    "CVE-2016-10197",
    "CVE-2017-5429",
    "CVE-2017-5430",
    "CVE-2017-5432",
    "CVE-2017-5433",
    "CVE-2017-5434",
    "CVE-2017-5435",
    "CVE-2017-5436",
    "CVE-2017-5437",
    "CVE-2017-5438",
    "CVE-2017-5439",
    "CVE-2017-5440",
    "CVE-2017-5441",
    "CVE-2017-5442",
    "CVE-2017-5443",
    "CVE-2017-5444",
    "CVE-2017-5445",
    "CVE-2017-5446",
    "CVE-2017-5447",
    "CVE-2017-5448",
    "CVE-2017-5449",
    "CVE-2017-5451",
    "CVE-2017-5454",
    "CVE-2017-5455",
    "CVE-2017-5456",
    "CVE-2017-5459",
    "CVE-2017-5460",
    "CVE-2017-5464",
    "CVE-2017-5465",
    "CVE-2017-5466",
    "CVE-2017-5467",
    "CVE-2017-5469"
  );

  script_name(english:"EulerOS 2.0 SP1 : firefox (EulerOS-SA-2017-1092)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the firefox package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Multiple flaws were found in the processing of
    malformed web content. A web page containing malicious
    content could cause Firefox to crash or, potentially,
    execute arbitrary code with the privileges of the user
    running Firefox. (CVE-2017-5429, CVE-2017-5430,
    CVE-2017-5432, CVE-2017-5433, CVE-2017-5434,
    CVE-2017-5435, CVE-2017-5436, CVE-2017-5437,
    CVE-2017-5438, CVE-2017-5439, CVE-2017-5440,
    CVE-2017-5441, CVE-2017-5442, CVE-2017-5443,
    CVE-2017-5444, CVE-2017-5445, CVE-2017-5446,
    CVE-2017-5447, CVE-2017-5448, CVE-2017-5449,
    CVE-2017-5451, CVE-2017-5454, CVE-2017-5455,
    CVE-2017-5456, CVE-2017-5459, CVE-2017-5460,
    CVE-2017-5464, CVE-2017-5465, CVE-2017-5466,
    CVE-2017-5467,
    CVE-2017-5469,CVE-2016-10195,CVE-2016-10196,CVE-2016-10
    197)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1092
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?969d46ef");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["firefox-52.1.0-2.0.1.h1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg, allowmaj:TRUE)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
