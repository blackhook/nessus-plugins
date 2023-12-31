#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0261 and 
# CentOS Errata and Security Advisory 2009:0261 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35651);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-4770");
  script_bugtraq_id(33263);
  script_xref(name:"RHSA", value:"2009:0261");

  script_name(english:"CentOS 3 / 4 : vnc (CESA-2009:0261)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vnc packages to correct a security issue are now available for
Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Virtual Network Computing (VNC) is a remote display system which
allows you to view a computer's 'desktop' environment not only on the
machine where it is running, but from anywhere on the Internet and
from a wide variety of machine architectures.

An insufficient input validation flaw was discovered in the VNC client
application, vncviewer. If an attacker could convince a victim to
connect to a malicious VNC server, or when an attacker was able to
connect to vncviewer running in the 'listen' mode, the attacker could
cause the victim's vncviewer to crash or, possibly, execute arbitrary
code. (CVE-2008-4770)

Users of vncviewer should upgrade to these updated packages, which
contain a backported patch to resolve this issue. For the update to
take effect, all running instances of vncviewer must be restarted
after the update is installed."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?967b175b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015630.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d276229"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015633.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d0fdf88"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015634.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?883b3d39"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015635.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4adbb0d3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015636.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8913c4e0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vnc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vnc-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"vnc-4.0-0.beta4.1.8")) flag++;
if (rpm_check(release:"CentOS-3", reference:"vnc-server-4.0-0.beta4.1.8")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vnc-4.0-12.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vnc-4.0-12.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vnc-4.0-12.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vnc-server-4.0-12.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vnc-server-4.0-12.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vnc-server-4.0-12.el4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vnc / vnc-server");
}
