#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1674 and 
# Oracle Linux Security Advisory ELSA-2013-1674 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71111);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4453");
  script_bugtraq_id(55713);
  script_xref(name:"RHSA", value:"2013:1674");

  script_name(english:"Oracle Linux 6 : dracut (ELSA-2013-1674)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1674 :

Updated dracut packages that fix one security issue, several bugs, and
add two enhancements are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The dracut packages include an event-driven initramfs generator
infrastructure based on the udev device manager. The virtual file
system, initramfs, is loaded together with the kernel at boot time and
initializes the system, so it can read and boot from the root
partition.

It was discovered that dracut created initramfs images as world
readable. A local user could possibly use this flaw to obtain
sensitive information from these files, such as iSCSI authentication
passwords, encrypted root file system crypttab passwords, or other
information. (CVE-2012-4453)

This issue was discovered by Peter Jones of the Red Hat Installer
Team.

These updated dracut packages include numerous bug fixes and two
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All dracut users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-November/003811.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dracut packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-caps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-fips-aesni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dracut-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"dracut-004-336.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"dracut-caps-004-336.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"dracut-fips-004-336.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"dracut-fips-aesni-004-336.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"dracut-generic-004-336.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"dracut-kernel-004-336.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"dracut-network-004-336.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"dracut-tools-004-336.0.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dracut / dracut-caps / dracut-fips / dracut-fips-aesni / etc");
}
