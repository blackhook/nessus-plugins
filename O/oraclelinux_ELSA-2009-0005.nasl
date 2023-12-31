#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0005 and 
# Oracle Linux Security Advisory ELSA-2009-0005 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67784);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-0706");
  script_xref(name:"RHSA", value:"2009:0005");

  script_name(english:"Oracle Linux 3 / 4 : gnome-vfs / gnome-vfs2 (ELSA-2009-0005)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0005 :

Updated GNOME VFS packages that fix a security issue are now available
for Red Hat Enterprise Linux 2.1, 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNOME VFS is the GNOME virtual file system. It provides a modular
architecture and ships with several modules that implement support for
various local and remote file systems as well as numerous protocols,
including HTTP, FTP, and others.

A buffer overflow flaw was discovered in the GNOME virtual file system
when handling data returned by CDDB servers. If a user connected to a
malicious CDDB server, an attacker could use this flaw to execute
arbitrary code on the victim's machine. (CVE-2005-0706)

Users of gnome-vfs and gnome-vfs2 are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue. All running GNOME sessions must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-January/000853.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-January/000854.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome-vfs and / or gnome-vfs2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-vfs2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-vfs2-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/08");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gnome-vfs2-2.2.5-2E.3.3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gnome-vfs2-2.2.5-2E.3.3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gnome-vfs2-devel-2.2.5-2E.3.3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gnome-vfs2-devel-2.2.5-2E.3.3")) flag++;

if (rpm_check(release:"EL4", reference:"gnome-vfs2-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"gnome-vfs2-devel-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"gnome-vfs2-smb-2.8.2-8.7.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"samba-3.0.28-0.0.2.el4.9")) flag++;
if (rpm_check(release:"EL4", reference:"samba-client-3.0.28-0.0.2.el4.9")) flag++;
if (rpm_check(release:"EL4", reference:"samba-common-3.0.28-0.0.2.el4.9")) flag++;
if (rpm_check(release:"EL4", reference:"samba-swat-3.0.28-0.0.2.el4.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-vfs2 / gnome-vfs2-devel / gnome-vfs2-smb / samba / etc");
}
