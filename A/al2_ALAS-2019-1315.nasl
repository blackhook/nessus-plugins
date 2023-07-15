#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1315.
#

include("compat.inc");

if (description)
{
  script_id(129851);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2017-1000367", "CVE-2017-1000368", "CVE-2019-14287");
  script_xref(name:"ALAS", value:"2019-1315");
  script_xref(name:"IAVA", value:"2019-A-0378-S");

  script_name(english:"Amazon Linux 2 : sudo (ALAS-2019-1315)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"When sudo is configured to allow a user to run commands as an
arbitrary user via the ALL keyword in a Runas specification, it is
possible to run commands as root by specifying the user ID -1 or
4294967295.

This can be used by a user with sufficient sudo privileges to run
commands as root even if the Runas specification explicitly disallows
root access as long as the ALL keyword is listed first in the Runas
specification. (CVE-2019-14287)

Further details can be found here:
https://www.sudo.ws/alerts/minus_1_uid.html

A flaw was found in the way sudo parsed tty information from the
process status file in the proc filesystem. A local user with
privileges to execute commands via sudo could use this flaw to
escalate their privileges to root.(CVE-2017-1000367)

It was found that the original fix for CVE-2017-1000367 was
incomplete. A flaw was found in the way sudo parsed tty information
from the process status file in the proc filesystem. A local user with
privileges to execute commands via sudo could use this flaw to
escalate their privileges to root.(CVE-2017-1000368)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1315.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update sudo' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14287");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sudo-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"sudo-1.8.23-4.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"sudo-debuginfo-1.8.23-4.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"sudo-devel-1.8.23-4.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo / sudo-debuginfo / sudo-devel");
}
