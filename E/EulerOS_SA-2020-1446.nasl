#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135608);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-9637",
    "CVE-2015-1196",
    "CVE-2015-1395",
    "CVE-2016-10713",
    "CVE-2018-20969",
    "CVE-2018-6952",
    "CVE-2019-13638"
  );
  script_bugtraq_id(
    72074,
    72286,
    72846
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : patch (EulerOS-SA-2020-1446)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the patch package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A double free exists in the another_hunk function in
    pch.c in GNU patch through 2.7.6.(CVE-2018-6952)

  - Directory traversal vulnerability in GNU patch versions
    which support Git-style patching before 2.7.3 allows
    remote attackers to write to arbitrary files with the
    permissions of the target user via a .. (dot dot) in a
    diff file name.(CVE-2015-1395)

  - An issue was discovered in GNU patch before 2.7.6.
    Out-of-bounds access within pch_write_line() in pch.c
    can possibly lead to DoS via a crafted input
    file.(CVE-2016-10713)

  - GNU patch 2.7.2 and earlier allows remote attackers to
    cause a denial of service (memory consumption and
    segmentation fault) via a crafted diff
    file.(CVE-2014-9637)

  - This vulnerability has been modified since it was last
    analyzed by the NVD. It is awaiting reanalysis which
    may result in further changes to the information
    provided.(CVE-2015-1196)

  - GNU patch through 2.7.6 is vulnerable to OS shell
    command injection that can be exploited by opening a
    crafted patch file that contains an ed style diff
    payload with shell metacharacters. The ed editor does
    not need to be present on the vulnerable system. This
    is different from CVE-2018-1000156.(CVE-2019-13638)

  - do_ed_script in pch.c in GNU patch through 2.7.6 does
    not block strings beginning with a ! character. NOTE:
    this is the same commit as for CVE-2019-13638, but the
    ! syntax is specific to ed, and is unrelated to a shell
    metacharacter.(CVE-2018-20969)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1446
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf754a63");
  script_set_attribute(attribute:"solution", value:
"Update the affected patch packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["patch-2.7.1-10.h3.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "patch");
}
