#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1349 and 
# CentOS Errata and Security Advisory 2011:1349 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56380);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-3378");
  script_bugtraq_id(49799);
  script_xref(name:"RHSA", value:"2011:1349");

  script_name(english:"CentOS 4 / 5 : rpm (CESA-2011:1349)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rpm packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6, and Red Hat
Enterprise Linux 3 Extended Life Cycle Support, 5.3 Long Life, 5.6
Extended Update Support, and 6.0 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The RPM Package Manager (RPM) is a command line driven package
management system capable of installing, uninstalling, verifying,
querying, and updating software packages.

Multiple flaws were found in the way the RPM library parsed package
headers. An attacker could create a specially crafted RPM package
that, when queried or installed, would cause rpm to crash or,
potentially, execute arbitrary code. (CVE-2011-3378)

Note: Although an RPM package can, by design, execute arbitrary code
when installed, this issue would allow a specially crafted RPM package
to execute arbitrary code before its digital signature has been
verified. Package downloads from the Red Hat Network remain secure due
to certificate checks performed on the secure connection.

All RPM users should upgrade to these updated packages, which contain
a backported patch to correct these issues. All running applications
linked against the RPM library must be restarted for this update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-November/018159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e271676f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-November/018160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c545a1a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-October/018091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6ff68a7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-October/018092.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?309460ed"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rpm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"popt-1.9.1-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"popt-1.9.1-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"rpm-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"rpm-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"rpm-build-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"rpm-build-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"rpm-devel-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"rpm-devel-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"rpm-libs-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"rpm-libs-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"rpm-python-4.3.3-35_nonptl.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"rpm-python-4.3.3-35_nonptl.el4_8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"popt-1.10.2.3-22.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-4.4.2.3-22.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-apidocs-4.4.2.3-22.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-build-4.4.2.3-22.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-devel-4.4.2.3-22.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-libs-4.4.2.3-22.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rpm-python-4.4.2.3-22.el5_7.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "popt / rpm / rpm-apidocs / rpm-build / rpm-devel / rpm-libs / etc");
}
