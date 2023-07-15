#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:373 and 
# CentOS Errata and Security Advisory 2005:373 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21812);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1740", "CVE-2005-2177", "CVE-2005-4837");
  script_xref(name:"RHSA", value:"2005:373");

  script_name(english:"CentOS 3 : net-snmp (CESA-2005:373)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix two security issues and various
bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

SNMP (Simple Network Management Protocol) is a protocol used for
network management.

A denial of service bug was found in the way net-snmp uses network
stream protocols. It is possible for a remote attacker to send a
net-snmp agent a specially crafted packet which will crash the agent.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-2177 to this issue.

An insecure temporary file usage bug was found in net-snmp's fixproc
command. It is possible for a local user to modify the content of
temporary files used by fixproc which can lead to arbitrary command
execution. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1740 to this issue.

Additionally the following bugs have been fixed: - snmpwalk no longer
hangs when a non-existent pid is listed. - snmpd no longer segfaults
due to incorrect handling of lmSensors. - an incorrect assignment
leading to invalid values in ASN mibs has been fixed. - on systems
running a 64-bit kernel, the values in /proc/net/dev no longer become
too large to fit in a 32-bit object. - the net-snmp-devel packages
correctly depend on elfutils-libelf-devel. - large file systems are
correctly handled - snmp daemon now reports gigabit Ethernet speeds
correctly - fixed consistency between IP adresses and hostnames in
configuration file

All users of net-snmp should upgrade to these updated packages, which
resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3348ce38"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012227.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba5f9b99"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf383689"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-5.0.9-2.30E.19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-devel-5.0.9-2.30E.19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-libs-5.0.9-2.30E.19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-perl-5.0.9-2.30E.19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"net-snmp-utils-5.0.9-2.30E.19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-devel / net-snmp-libs / net-snmp-perl / etc");
}
