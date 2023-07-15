#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0513 and 
# CentOS Errata and Security Advisory 2007:0513 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26203);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4519", "CVE-2007-2949", "CVE-2007-3741");
  script_bugtraq_id(24745);
  script_xref(name:"RHSA", value:"2007:0513");

  script_name(english:"CentOS 3 / 4 / 5 : gimp (CESA-2007:0513)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gimp packages that fix several security issues are now
available for Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

Multiple integer overflow and input validation flaws were found in The
GIMP's image loaders. An attacker could create a carefully crafted
image file that could cause The GIMP to crash or possibly execute
arbitrary code if the file was opened by a victim. (CVE-2006-4519,
CVE-2007-2949, CVE-2007-3741)

Users of The GIMP should update to these erratum packages, which
contain a backported fix to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014238.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd414fe0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014239.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e6d6fa4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba9caef4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014241.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e68fce7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ccf73f7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014254.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90c0501e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ba93c7c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f557d923"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"gimp-1.2.3-20.9.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gimp-devel-1.2.3-20.9.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gimp-perl-1.2.3-20.9.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gimp-2.0.5-7.0.7.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gimp-devel-2.0.5-7.0.7.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"gimp-2.2.13-2.0.7.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gimp-devel-2.2.13-2.0.7.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gimp-libs-2.2.13-2.0.7.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-devel / gimp-libs / gimp-perl");
}
