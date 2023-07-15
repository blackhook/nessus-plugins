#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:638 and 
# CentOS Errata and Security Advisory 2004:638 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21793);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0941", "CVE-2004-0990");
  script_bugtraq_id(11523);
  script_xref(name:"RHSA", value:"2004:638");

  script_name(english:"CentOS 3 : gd (CESA-2004:638)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gd packages that fix security issues with overflow in various
memory allocation calls are now available.

[Updated 24 May 2005] Multilib packages have been added to this
advisory

The gd packages contain a graphics library used for the dynamic
creation of images such as PNG and JPEG.

Several buffer overflows were reported in various memory allocation
calls. An attacker could create a carefully crafted image file in such
a way that it could cause ImageMagick to execute arbitrary code when
processing the image. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0990 to these issues.

While researching the fixes to these overflows, additional buffer
overflows were discovered in calls to gdMalloc. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0941 to these issues.

Users of gd should upgrade to these updated packages, which contain a
backported security patch, and are not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011767.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19f59d09"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c87e301"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/27");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gd-1.8.4-12.3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gd-1.8.4-12.3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gd-devel-1.8.4-12.3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gd-devel-1.8.4-12.3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gd-progs-1.8.4-12.3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gd-progs-1.8.4-12.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gd / gd-devel / gd-progs");
}
