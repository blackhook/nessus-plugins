#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1100 and 
# CentOS Errata and Security Advisory 2009:1100 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39423);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1210", "CVE-2009-1268", "CVE-2009-1269", "CVE-2009-1829");
  script_bugtraq_id(34291, 34457, 35081);
  script_xref(name:"RHSA", value:"2009:1100");

  script_name(english:"CentOS 3 / 5 : wireshark (CESA-2009:1100)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wireshark packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Wireshark is a program for monitoring network traffic. Wireshark was
previously known as Ethereal.

A format string flaw was found in Wireshark. If Wireshark read a
malformed packet off a network or opened a malicious dump file, it
could crash or, possibly, execute arbitrary code as the user running
Wireshark. (CVE-2009-1210)

Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2009-1268,
CVE-2009-1269, CVE-2009-1829)

Users of wireshark should upgrade to these updated packages, which
contain Wireshark version 1.0.8, and resolve these issues. All running
instances of Wireshark must be restarted for the update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015969.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d86da88"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9391ad84"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015987.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1a676ad"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21f60253"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wireshark-1.0.8-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wireshark-1.0.8-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wireshark-gnome-1.0.8-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wireshark-gnome-1.0.8-EL3.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"wireshark-1.0.8-1.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"wireshark-gnome-1.0.8-1.el5_3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-gnome");
}
