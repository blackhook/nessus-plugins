#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0382 and 
# CentOS Errata and Security Advisory 2010:0382 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46758);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-1166");
  script_xref(name:"RHSA", value:"2010:0382");

  script_name(english:"CentOS 5 : xorg-x11-server (CESA-2010:0382)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-server packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

An incorrect calculation flaw was discovered in the X.Org Render
extension. A malicious, authorized client could exploit this issue to
crash the X.Org server or, potentially, execute arbitrary code with
root privileges. (CVE-2010-1166)

Users of xorg-x11-server should upgrade to these updated packages,
which contain a backported patch to resolve this issue. All running
X.Org server instances must be restarted for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016649.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd1c9a06"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016651.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81b7345a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvnc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xdmx-1.1.1-48.76.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xephyr-1.1.1-48.76.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xnest-1.1.1-48.76.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xorg-1.1.1-48.76.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xvfb-1.1.1-48.76.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.76.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-sdk-1.1.1-48.76.el5_5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
}
