#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0457 and 
# CentOS Errata and Security Advisory 2009:0457 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38900);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1364");
  script_xref(name:"RHSA", value:"2009:0457");

  script_name(english:"CentOS 4 / 5 : libwmf (CESA-2009:0457)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libwmf packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

libwmf is a library for reading and converting Windows Metafile Format
(WMF) vector graphics. libwmf is used by applications such as GIMP and
ImageMagick.

A pointer use-after-free flaw was found in the GD graphics library
embedded in libwmf. An attacker could create a specially crafted WMF
file that would cause an application using libwmf to crash or,
potentially, execute arbitrary code as the user running the
application when opened by a victim. (CVE-2009-1364)

Note: This flaw is specific to the GD graphics library embedded in
libwmf. It does not affect the GD graphics library from the 'gd'
packages, or applications using it.

Red Hat would like to thank Tavis Ormandy of the Google Security Team
for responsibly reporting this flaw.

All users of libwmf are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, all applications using libwmf must be restarted
for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b3cc73f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015871.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf7e924a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015872.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdcd2517"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015922.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?026320c3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015923.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c499a1b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwmf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwmf-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"libwmf-0.2.8.3-5.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libwmf-devel-0.2.8.3-5.8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libwmf-0.2.8.4-10.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libwmf-devel-0.2.8.4-10.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwmf / libwmf-devel");
}
