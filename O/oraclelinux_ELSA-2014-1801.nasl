#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1801 and 
# Oracle Linux Security Advisory ELSA-2014-1801 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78882);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3675", "CVE-2014-3676", "CVE-2014-3677");
  script_bugtraq_id(70407, 70409, 70410);
  script_xref(name:"RHSA", value:"2014:1801");

  script_name(english:"Oracle Linux 7 : shim (ELSA-2014-1801)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1801 :

Updated shim packages that fix three security issues are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Shim is the initial UEFI bootloader that handles chaining to a trusted
full bootloader under secure boot environments.

A heap-based buffer overflow flaw was found the way shim parsed
certain IPv6 addresses. If IPv6 network booting was enabled, a
malicious server could supply a crafted IPv6 address that would cause
shim to crash or, potentially, execute arbitrary code. (CVE-2014-3676)

An out-of-bounds memory write flaw was found in the way shim processed
certain Machine Owner Keys (MOKs). A local attacker could potentially
use this flaw to execute arbitrary code on the system. (CVE-2014-3677)

An out-of-bounds memory read flaw was found in the way shim parsed
certain IPv6 packets. A specially crafted DHCPv6 packet could possibly
cause shim to crash, preventing the system from booting if IPv6
booting was enabled. (CVE-2014-3675)

Red Hat would like to thank the SUSE Security Team for reporting these
issues.

All shim users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-November/004617.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected shim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mokutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:shim-unsigned");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mokutil-0.7-8.0.1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"shim-0.7-8.0.1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"shim-unsigned-0.7-8.0.1.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mokutil / shim / shim-unsigned");
}
