#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1646 and 
# Oracle Linux Security Advisory ELSA-2009-1646 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67968);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_xref(name:"RHSA", value:"2009:1646");

  script_name(english:"Oracle Linux 3 / 4 / 5 : libtool (ELSA-2009-1646)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1646 :

Updated libtool packages that fix one security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNU Libtool is a set of shell scripts which automatically configure
UNIX, Linux, and similar operating systems to generically build shared
libraries.

A flaw was found in the way GNU Libtool's libltdl library looked for
modules to load. It was possible for libltdl to load and run modules
from an arbitrary library in the current working directory. If a local
attacker could trick a local user into running an application (which
uses libltdl) from an attacker-controlled directory containing a
malicious Libtool control file (.la), the attacker could possibly
execute arbitrary code with the privileges of the user running the
application. (CVE-2009-3736)

All libtool users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, applications using the libltdl library must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-December/001276.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-December/001278.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-December/001280.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtool packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtool-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtool-ltdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtool-ltdl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libtool-1.4.3-7")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libtool-1.4.3-7")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libtool-libs-1.4.3-7")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libtool-libs-1.4.3-7")) flag++;

if (rpm_check(release:"EL4", reference:"libtool-1.5.6-5.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"libtool-libs-1.5.6-5.el4_8")) flag++;

if (rpm_check(release:"EL5", reference:"libtool-1.5.22-7.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"libtool-ltdl-1.5.22-7.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"libtool-ltdl-devel-1.5.22-7.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtool / libtool-libs / libtool-ltdl / libtool-ltdl-devel");
}
