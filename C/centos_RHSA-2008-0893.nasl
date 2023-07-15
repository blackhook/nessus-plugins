#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0893 and 
# CentOS Errata and Security Advisory 2008:0893 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34222);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1372");
  script_xref(name:"RHSA", value:"2008:0893");

  script_name(english:"CentOS 3 / 4 / 5 : bzip2 (CESA-2008:0893)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bzip2 packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Bzip2 is a freely available, high-quality data compressor. It provides
both stand-alone compression and decompression utilities, as well as a
shared library for use with other programs.

A buffer over-read flaw was discovered in the bzip2 decompression
routine. This issue could cause an application linked against the
libbz2 library to crash when decompressing malformed archives.
(CVE-2008-1372)

Users of bzip2 should upgrade to these updated packages, which contain
a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-September/015250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21ee8db8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-September/015251.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6c77cd5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-September/015252.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd4d2bd0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-September/015253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6e63dd1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-September/015257.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd86536c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-September/015258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a7a7a22"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-September/015259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7671a1be"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-September/015261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7943e8b1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzip2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bzip2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/17");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"bzip2-1.0.2-12.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bzip2-devel-1.0.2-12.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bzip2-libs-1.0.2-12.EL3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bzip2-1.0.2-14.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bzip2-1.0.2-14.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bzip2-1.0.2-14.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bzip2-devel-1.0.2-14.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bzip2-devel-1.0.2-14.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bzip2-devel-1.0.2-14.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"bzip2-libs-1.0.2-14.el4_7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"bzip2-libs-1.0.2-14.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"bzip2-libs-1.0.2-14.el4_7")) flag++;

if (rpm_check(release:"CentOS-5", reference:"bzip2-1.0.3-4.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bzip2-devel-1.0.3-4.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bzip2-libs-1.0.3-4.el5_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bzip2 / bzip2-devel / bzip2-libs");
}
