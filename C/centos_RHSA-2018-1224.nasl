#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1224 and 
# CentOS Errata and Security Advisory 2018:1224 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110243);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-1106");
  script_xref(name:"RHSA", value:"2018:1224");

  script_name(english:"CentOS 7 : PackageKit (CESA-2018:1224)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for PackageKit is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PackageKit is a D-Bus abstraction layer that allows the session user
to manage packages in a secure way using a cross-distribution,
cross-architecture API.

Security Fix(es) :

* PackageKit: authentication bypass allows to install signed packages
without administrator privileges (CVE-2018-1106)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Matthias Gerstner (SUSE) for reporting
this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-May/022891.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec2f3d44"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected packagekit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1106");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-command-not-found");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PackageKit-yum-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-1.1.5-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-command-not-found-1.1.5-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-cron-1.1.5-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-glib-1.1.5-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-glib-devel-1.1.5-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-gstreamer-plugin-1.1.5-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-gtk3-module-1.1.5-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-yum-1.1.5-2.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"PackageKit-yum-plugin-1.1.5-2.el7.centos")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / PackageKit-command-not-found / PackageKit-cron / etc");
}
