#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0020.
#

include("compat.inc");

if (description)
{
  script_id(137217);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/13");

  script_cve_id("CVE-2017-1000370", "CVE-2017-1000371", "CVE-2018-18281", "CVE-2019-12819", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-19057", "CVE-2019-19524", "CVE-2019-19528", "CVE-2019-19537", "CVE-2019-20636", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2020-0020) (Stack Clash)");
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

  - Input: ff-memless - kill timer in destroy (Oliver
    Neukum) [Orabug: 31213691] (CVE-2019-19524)

  - libertas: Fix two buffer overflows at parsing bss
    descriptor (Wen Huang) [Orabug: 31351307]
    (CVE-2019-14896) (CVE-2019-14897) (CVE-2019-14897)

  - binfmt_elf: use ELF_ET_DYN_BASE only for PIE (Kees Cook)
    [Orabug: 31352068] (CVE-2017-1000370) (CVE-2017-1000371)
    (CVE-2017-1000370)

  - NFSv4.0: Remove transport protocol name from non-UCS
    client ID (Chuck Lever) [Orabug: 31357212]

  - NFSv4.0: Remove cl_ipaddr from non-UCS client ID (Chuck
    Lever) 

  - xen/manage: enable C_A_D to force reboot (Dongli Zhang)
    [Orabug: 31387466]

  - acpi: disable erst (Wengang Wang) [Orabug: 31194253]

  - mdio_bus: Fix use-after-free on device_register fails
    (YueHaibing) [Orabug: 31222292] (CVE-2019-12819)

  - rds: ib: Fix dysfunctional long address resolve timeout
    (Hakon Bugge) 

  - vxlan: don't migrate permanent fdb entries during learn
    (Roopa Prabhu) 

  - USB: iowarrior: fix use-after-free on disconnect (Johan
    Hovold) [Orabug: 31351061] (CVE-2019-19528)

  - usb: iowarrior: fix deadlock on disconnect (Oliver
    Neukum) [Orabug: 31351061] (CVE-2019-19528)

  - mremap: properly flush TLB before releasing the page
    (Linus Torvalds) [Orabug: 31352011] (CVE-2018-18281)

  - Input: add safety guards to input_set_keycode (Dmitry
    Torokhov) [Orabug: 31200558] (CVE-2019-20636)

  - media: stv06xx: add missing descriptor sanity checks
    (Johan Hovold) [Orabug: 31200579] (CVE-2020-11609)

  - media: ov519: add missing endpoint sanity checks (Johan
    Hovold) [Orabug: 31213758] (CVE-2020-11608)

  - media: xirlink_cit: add missing descriptor sanity checks
    (Johan Hovold) [Orabug: 31213767] (CVE-2020-11668)

  - mwifiex: pcie: Fix memory leak in
    mwifiex_pcie_init_evt_ring (Navid Emamdoost) [Orabug:
    31263147] (CVE-2019-19057)

  - USB: core: Fix races in character device registration
    and deregistraion (Alan Stern) [Orabug: 31317667]
    (CVE-2019-19537)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-June/000983.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.39.5.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.39.5.el6uek")) flag++;

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
