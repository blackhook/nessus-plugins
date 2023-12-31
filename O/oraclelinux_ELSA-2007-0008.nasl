#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0008 and 
# Oracle Linux Security Advisory ELSA-2007-0008 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67436);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-6107");
  script_xref(name:"RHSA", value:"2007:0008");

  script_name(english:"Oracle Linux 4 : dbus (ELSA-2007-0008)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0008 :

Updated dbus packages that fix a security issue are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

D-BUS is a system for sending messages between applications. It is
used both for the systemwide message bus service, and as a
per-user-login-session messaging facility.

Kimmo Hamalainen discovered a flaw in the way D-BUS processes certain
messages. It is possible for a local unprivileged D-BUS process to
disrupt the ability of another D-BUS process to receive messages.
(CVE-2006-6107)

Users of dbus are advised to upgrade to these updated packages, which
contain backported patches to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-February/000049.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dbus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dbus-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dbus-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/09");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"dbus-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"dbus-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"dbus-devel-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"dbus-devel-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"dbus-glib-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"dbus-glib-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"dbus-python-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"dbus-python-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"dbus-x11-0.22-12.EL.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"dbus-x11-0.22-12.EL.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus / dbus-devel / dbus-glib / dbus-python / dbus-x11");
}
