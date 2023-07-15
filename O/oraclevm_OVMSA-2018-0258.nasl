#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0258.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(117764);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/04");

  script_cve_id("CVE-2017-13695", "CVE-2018-16658", "CVE-2018-5873");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0258)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - nsfs: mark dentry with DCACHE_RCUACCESS (Cong Wang)
    [Orabug: 28576290] (CVE-2018-5873)

  - dm crypt: add middle-endian variant of plain64 IV
    (Konrad Rzeszutek Wilk) [Orabug: 28604628]

  - IB/ipoib: Improve filtering log message (Yuval Shaia)
    [Orabug: 28655409]

  - IB/ipoib: Fix wrong update of arp_blocked counter (Yuval
    Shaia) 

  - IB/ipoib: Update RX counters after ACL filtering (Yuval
    Shaia) 

  - IB/ipoib: Filter RX packets before adding pseudo header
    (Yuval Shaia) 

  - cdrom: Fix info leak/OOB read in
    cdrom_ioctl_drive_status (Scott Bauer) [Orabug:
    28664501] (CVE-2018-16658)

  - ACPICA: acpi: acpica: fix acpi operand cache leak in
    nseval.c (Seunghun Han) [Orabug: 28664577]
    (CVE-2017-13695)

  - uek-rpm: Disable deprecated CONFIG_ACPI_PROCFS_POWER
    (Victor Erminpour) [Orabug: 28680213]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-September/000893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?851cd234"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5873");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.19.5.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.19.5.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
