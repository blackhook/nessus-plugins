#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124927);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-7345",
    "CVE-2014-0207",
    "CVE-2014-0237",
    "CVE-2014-0238",
    "CVE-2014-2270",
    "CVE-2014-3478",
    "CVE-2014-3479",
    "CVE-2014-3480",
    "CVE-2014-3487",
    "CVE-2014-3538",
    "CVE-2014-3587",
    "CVE-2014-8117",
    "CVE-2014-9652",
    "CVE-2014-9653"
  );
  script_bugtraq_id(
    66002,
    66406,
    67759,
    67765,
    68120,
    68238,
    68239,
    68241,
    68243,
    68348,
    69325,
    71692,
    72505,
    72516
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : file (EulerOS-SA-2019-1424)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the file packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A denial of service flaw was found in the File
    Information (fileinfo) extension rules for detecting
    AWK files. A remote attacker could use this flaw to
    cause a PHP application using fileinfo to consume an
    excessive amount of CPU.(CVE-2013-7345)

  - A denial of service flaw was found in the way the File
    Information (fileinfo) extension parsed certain
    Composite Document Format (CDF) files. A remote
    attacker could use this flaw to crash a PHP application
    using fileinfo via a specially crafted CDF
    file.(CVE-2014-3479)

  - An ouf-of-bounds read flaw was found in the way the
    file utility processed certain Pascal strings. A remote
    attacker could cause an application using the file
    utility (for example, PHP using the fileinfo module) to
    crash if it was used to identify the type of the
    attacker-supplied file.(CVE-2014-9652)

  - A denial of service flaw was found in the way the File
    Information (fileinfo) extension parsed certain
    Composite Document Format (CDF) files. A remote
    attacker could use this flaw to crash a PHP application
    using fileinfo via a specially crafted CDF
    file.(CVE-2014-0207)

  - A denial of service flaw was found in the way the File
    Information (fileinfo) extension parsed certain
    Composite Document Format (CDF) files. A remote
    attacker could use this flaw to crash a PHP application
    using fileinfo via a specially crafted CDF
    file.(CVE-2014-3480)

  - It was found that the fix for CVE-2012-1571 was
    incomplete the File Information (fileinfo) extension
    did not correctly parse certain Composite Document
    Format (CDF) files. A remote attacker could use this
    flaw to crash a PHP application using fileinfo via a
    specially crafted CDF file.(CVE-2014-3587)

  - A buffer overflow flaw was found in the way the File
    Information (fileinfo) extension processed certain
    Pascal strings. A remote attacker able to make a PHP
    application using fileinfo convert a specially crafted
    Pascal string provided by an image file could cause
    that application to crash.(CVE-2014-3478)

  - Multiple flaws were found in the File Information
    (fileinfo) extension regular expression rules for
    detecting various files. A remote attacker could use
    either of these flaws to cause a PHP application using
    fileinfo to consume an excessive amount of
    CPU.(CVE-2014-3538)

  - A denial of service flaw was found in the way the File
    Information (fileinfo) extension parsed certain
    Composite Document Format (CDF) files. A remote
    attacker could use this flaw to crash a PHP application
    using fileinfo via a specially crafted CDF
    file.(CVE-2014-3487)

  - A denial of service flaw was found in the way the File
    Information (fileinfo) extension handled search rules.
    A remote attacker could use this flaw to cause a PHP
    application using fileinfo to crash or consume an
    excessive amount of CPU.(CVE-2014-2270)

  - A flaw was found in the way the File Information
    (fileinfo) extension parsed Executable and Linkable
    Format (ELF) files. A remote attacker could use this
    flaw to cause a PHP application using fileinfo to
    consume an excessive amount of system
    resources.(CVE-2014-8117)

  - A denial of service flaw was found in the way the File
    Information (fileinfo) extension parsed certain
    Composite Document Format (CDF) files. A remote
    attacker could use this flaw to crash a PHP application
    using fileinfo via a specially crafted CDF
    file.(CVE-2014-0237)

  - A flaw was found in the way the File Information
    (fileinfo) extension parsed Executable and Linkable
    Format (ELF) files. A remote attacker could use this
    flaw to cause a PHP application using fileinfo to crash
    or disclose certain portions of server
    memory.(CVE-2014-9653)

  - A denial of service flaw was found in the way the File
    Information (fileinfo) extension parsed certain
    Composite Document Format (CDF) files. A remote
    attacker could use this flaw to crash a PHP application
    using fileinfo via a specially crafted CDF
    file.(CVE-2014-0238)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1424
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a6a5c24");
  script_set_attribute(attribute:"solution", value:
"Update the affected file packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:file-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["file-5.11-33.eulerosv2r7",
        "file-libs-5.11-33.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file");
}
