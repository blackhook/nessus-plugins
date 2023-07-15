#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0308 and 
# CentOS Errata and Security Advisory 2009:0308 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35719);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3640", "CVE-2009-0577");
  script_bugtraq_id(31690);
  script_xref(name:"RHSA", value:"2009:0308");

  script_name(english:"CentOS 3 / 4 : cups (CESA-2009:0308)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix a security issue are now available for
Red Hat Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX(r) Printing System (CUPS) provides a portable printing
layer for UNIX operating systems.

The CUPS security advisory, RHSA-2008:0937, stated that it fixed
CVE-2008-3640 for Red Hat Enterprise Linux 3, 4, and 5. It was
discovered this flaw was not properly fixed on Red Hat Enterprise
Linux 3, however. (CVE-2009-0577)

These new packages contain a proper fix for CVE-2008-3640 on Red Hat
Enterprise Linux 3. Red Hat Enterprise Linux 4 and 5 already contain
the appropriate fix for this flaw and do not need to be updated.

Users of cups should upgrade to these updated packages, which contain
a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3acea5c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?440bffae"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015648.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aa1c724"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/20");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cups-1.1.17-13.3.56")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cups-1.1.17-13.3.56")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cups-devel-1.1.17-13.3.56")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cups-devel-1.1.17-13.3.56")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cups-libs-1.1.17-13.3.56")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cups-libs-1.1.17-13.3.56")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-1.1.17-13.3.56")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-devel-1.1.17-13.3.56")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-libs-1.1.17-13.3.56")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
}
