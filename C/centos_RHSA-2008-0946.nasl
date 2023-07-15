#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0946 and 
# CentOS Errata and Security Advisory 2008:0946 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34463);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3916");
  script_xref(name:"RHSA", value:"2008:0946");

  script_name(english:"CentOS 3 / 4 / 5 : ed (CESA-2008:0946)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ed package that fixes one security issue is now available
for Red Hat Enterprise Linux 2.1, 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ed is a line-oriented text editor, used to create, display, and modify
text files (both interactively and via shell scripts).

A heap-based buffer overflow was discovered in the way ed, the GNU
line editor, processed long file names. An attacker could create a
file with a specially crafted name that could possibly execute an
arbitrary code when opened in the ed editor. (CVE-2008-3916)

Users of ed should upgrade to this updated package, which contains a
backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015334.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31fcd362"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33b2aa02"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015338.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?145e1232"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015339.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e64595e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8c3e8c5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da959056"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57fa8591"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015357.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8291e608"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ed package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ed");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/22");
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
if (rpm_check(release:"CentOS-3", reference:"ed-0.2-33.30E.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ed-0.2-36.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ed-0.2-36.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ed-0.2-36.el4_7.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ed-0.2-39.el5_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ed");
}
