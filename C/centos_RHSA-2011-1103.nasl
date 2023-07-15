#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1103 and 
# CentOS Errata and Security Advisory 2011:1103 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55838);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2692");
  script_xref(name:"RHSA", value:"2011:1103");

  script_name(english:"CentOS 4 : libpng (CESA-2011:1103)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng and libpng10 packages that fix one security issue are
now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

An uninitialized memory read issue was found in the way libpng
processed certain PNG images that use the Physical Scale (sCAL)
extension. An attacker could create a specially crafted PNG image
that, when opened, could cause an application using libpng to crash.
(CVE-2011-2692)

Users of libpng and libpng10 should upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
applications using libpng or libpng10 must be restarted for the update
to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017667.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?034b4ad3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017668.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e599468e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng-1.2.7-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng-1.2.7-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng-devel-1.2.7-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng-devel-1.2.7-8.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng10-1.0.16-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng10-1.0.16-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng10-devel-1.0.16-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng10-devel-1.0.16-9.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-devel / libpng10 / libpng10-devel");
}
