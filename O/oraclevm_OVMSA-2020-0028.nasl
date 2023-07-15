#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0028.
#

include("compat.inc");

if (description)
{
  script_id(138416);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/16");

  script_cve_id("CVE-2017-16538", "CVE-2019-15214", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19536", "CVE-2020-0543");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2020-0028)");
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

  - ipv4: ipv4_default_advmss should use route mtu (Eric
    Dumazet) [Orabug: 31563095]

  - net: ipv4: Refine the ipv4_default_advmss (Gao Feng)
    [Orabug: 31563095]

  - Revert 'bnxt_en: Remove busy poll logic in the driver.'
    (Brian Maly) [Orabug: 28151475]

  - md: batch flush requests. (NeilBrown) [Orabug: 31332821]

  - ALSA: core: Fix card races between register and
    disconnect (Takashi Iwai) [Orabug: 31351891]
    (CVE-2019-15214)

  - media: dvb-usb-v2: lmedm04: move ts2020 attach to
    dm04_lme2510_tuner (Malcolm Priestley) [Orabug:
    31352061] (CVE-2017-16538)

  - media: dvb-usb-v2: lmedm04: Improve logic checking of
    warm start (Malcolm Priestley) [Orabug: 31352061]
    (CVE-2017-16538)

  - atomic_open: fix the handling of create_error (Al Viro)
    [Orabug: 31493395]

  - media: ttusb-dec: Fix info-leak in
    ttusb_dec_send_command (Tomas Bortoli) [Orabug:
    31351119] (CVE-2019-19533)

  - NFS: Fix a performance regression in readdir (Trond
    Myklebust) [Orabug: 31409061]

  - x86/speculation: Add Ivy Bridge to affected list (Josh
    Poimboeuf) [Orabug: 31475612] (CVE-2020-0543)

  - x86/speculation: Add SRBDS vulnerability and mitigation
    documentation (Mark Gross) [Orabug: 31475612]
    (CVE-2020-0543)

  - x86/speculation: Add Special Register Buffer Data
    Sampling (SRBDS) mitigation (Mark Gross) [Orabug:
    31475612] (CVE-2020-0543)

  - x86/cpu: Add 'table' argument to cpu_matches (Mark
    Gross) [Orabug: 31475612] (CVE-2020-0543)

  - x86/cpu: Add a steppings field to struct x86_cpu_id
    (Mark Gross) [Orabug: 31475612] (CVE-2020-0543)

  - x86/cpu: Rename cpu_data.x86_mask to
    cpu_data.x86_stepping (Jia Zhang) [Orabug: 31475612]
    (CVE-2020-0543)

  - MCE: Restrict MCE banks to 6 on AMD platform (Zhenzhong
    Duan) [Orabug: 30000521]

  - can: peak_usb: fix slab info leak (Johan Hovold)
    [Orabug: 31351141] (CVE-2019-19534)

  - can: peak_usb: pcan_usb_pro: Fix info-leaks to USB
    devices (Tomas Bortoli) [Orabug: 31351250]
    (CVE-2019-19536)

  - xfs: fix freeze hung (Junxiao Bi) [Orabug: 31430876]

  - iscsi_target: fix mismatch spinlock unlock (Junxiao Bi)
    [Orabug: 31202372]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-July/000989.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.40.6.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.40.6.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
