#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1536 and 
# Oracle Linux Security Advisory ELSA-2009-1536 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67951);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3615");
  script_xref(name:"RHSA", value:"2009:1536");

  script_name(english:"Oracle Linux 4 : pidgin (ELSA-2009-1536)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1536 :

Updated pidgin packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously. The
AOL Open System for Communication in Realtime (OSCAR) protocol is used
by the AOL ICQ and AIM instant messaging systems.

An invalid pointer dereference bug was found in the way the Pidgin
OSCAR protocol implementation processed lists of contacts. A remote
attacker could send a specially crafted contact list to a user running
Pidgin, causing Pidgin to crash. (CVE-2009-3615)

These packages upgrade Pidgin to version 2.6.3. Refer to the Pidgin
release notes for a full list of changes:
http://developer.pidgin.im/wiki/ChangeLog

All Pidgin users should upgrade to these updated packages, which
correct this issue. Pidgin must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-October/001228.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/29");
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
if (rpm_check(release:"EL4", reference:"finch-2.6.3-2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"finch-devel-2.6.3-2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-2.6.3-2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-devel-2.6.3-2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-perl-2.6.3-2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"libpurple-tcl-2.6.3-2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-2.6.3-2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-devel-2.6.3-2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"pidgin-perl-2.6.3-2.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
}
