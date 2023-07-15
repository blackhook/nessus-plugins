#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0003 and 
# CentOS Errata and Security Advisory 2010:0003 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43625);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-3546");
  script_bugtraq_id(36712);
  script_xref(name:"RHSA", value:"2010:0003");

  script_name(english:"CentOS 4 / 5 : gd (CESA-2010:0003)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gd packages that fix a security issue are now available for
Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gd packages provide a graphics library used for the dynamic
creation of images, such as PNG and JPEG.

A missing input sanitization flaw, leading to a buffer overflow, was
discovered in the gd library. A specially crafted GD image file could
cause an application using the gd library to crash or, possibly,
execute arbitrary code when opened. (CVE-2009-3546)

Users of gd should upgrade to these updated packages, which contain a
backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016409.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?477576df"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb6b5deb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?920acc8a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-January/016414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?136a1ac7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gd-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/05");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gd-2.0.28-5.4E.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gd-2.0.28-5.4E.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gd-devel-2.0.28-5.4E.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gd-devel-2.0.28-5.4E.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gd-progs-2.0.28-5.4E.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gd-progs-2.0.28-5.4E.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"gd-2.0.33-9.4.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gd-devel-2.0.33-9.4.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gd-progs-2.0.33-9.4.el5_4.2")) flag++;


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
