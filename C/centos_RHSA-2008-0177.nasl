#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0177 and 
# CentOS Errata and Security Advisory 2008:0177 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31424);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-0072");
  script_bugtraq_id(28102);
  script_xref(name:"RHSA", value:"2008:0177");

  script_name(english:"CentOS 4 / 5 : evolution (CESA-2008:0177)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix a format string bug are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Evolution is the GNOME collection of personal information management
(PIM) tools.

A format string flaw was found in the way Evolution displayed
encrypted mail content. If a user opened a carefully crafted mail
message, arbitrary code could be executed as the user running
Evolution. (CVE-2008-0072)

All users of Evolution should upgrade to these updated packages, which
contain a backported patch which resolves this issue.

Red Hat would like to thank Ulf Harnhammar of Secunia Research for
finding and reporting this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-March/014742.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?579d3666"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-March/014748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ac1c2bd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-March/014749.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc7bd0ea"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-March/014750.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68b8ca8b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-March/014751.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e540205"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"evolution-2.0.2-35.0.4.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"evolution-2.0.2-35.0.4.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"evolution-2.0.2-35.0.4.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"evolution-devel-2.0.2-35.0.4.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"evolution-devel-2.0.2-35.0.4.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"evolution-devel-2.0.2-35.0.4.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution28-2.8.0-53.el4_6.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution28-devel-2.8.0-53.el4_6.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"evolution-2.8.0-40.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"evolution-devel-2.8.0-40.el5_1.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution / evolution-devel / evolution28 / evolution28-devel");
}
