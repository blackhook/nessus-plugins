#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134555);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-5525",
    "CVE-2017-5526",
    "CVE-2017-5898",
    "CVE-2017-5973",
    "CVE-2017-5987",
    "CVE-2018-16872",
    "CVE-2018-19364",
    "CVE-2018-19489",
    "CVE-2019-3812",
    "CVE-2019-6778"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : qemu-kvm (EulerOS-SA-2020-1266)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - In QEMU 3.0.0, tcp_emu in slirp/tcp_subr.c has a
    heap-based buffer overflow.(CVE-2019-6778)

  - A flaw was found in QEMU's Media Transfer Protocol
    (MTP). The code opening files in usb_mtp_get_object and
    usb_mtp_get_partial_object and directories in
    usb_mtp_object_readdir doesn't consider that the
    underlying filesystem may have changed since the time
    lstat(2) was called in usb_mtp_object_alloc, a
    classical TOCTTOU problem. An attacker with write
    access to the host filesystem, shared with a guest, can
    use this property to navigate the host filesystem in
    the context of the QEMU process and read any file the
    QEMU process has access to. Access to the filesystem
    may be local or via a network share protocol such as
    CIFS.(CVE-2018-16872)

  - hw/9pfs/cofile.c and hw/9pfs/9p.c in QEMU can modify an
    fid path while it is being accessed by a second thread,
    leading to (for example) a use-after-free
    outcome.(CVE-2018-19364)

  - v9fs_wstat in hw/9pfs/9p.c in QEMU allows guest OS
    users to cause a denial of service (crash) because of a
    race condition during file renaming.(CVE-2018-19489)

  - QEMU, through version 2.10 and through version 3.1.0,
    is vulnerable to an out-of-bounds read of up to 128
    bytes in the hw/i2c/i2c-ddc.c:i2c_ddc() function. A
    local attacker with permission to execute i2c commands
    could exploit this to read stack memory of the qemu
    process on the host.(CVE-2019-3812)

  - Memory leak in hw/audio/ac97.c in QEMU (aka Quick
    Emulator) allows local guest OS privileged users to
    cause a denial of service (host memory consumption and
    QEMU process crash) via a large number of device unplug
    operations.(CVE-2017-5525)

  - Memory leak in hw/audio/es1370.c in QEMU (aka Quick
    Emulator) allows local guest OS privileged users to
    cause a denial of service (host memory consumption and
    QEMU process crash) via a large number of device unplug
    operations.(CVE-2017-5526)

  - The sdhci_sdma_transfer_multi_blocks function in
    hw/sd/sdhci.c in QEMU (aka Quick Emulator) allows local
    OS guest privileged users to cause a denial of service
    (infinite loop and QEMU process crash) via vectors
    involving the transfer mode register during multi block
    transfer.(CVE-2017-5987)

  - An integer overflow flaw was found in Quick Emulator
    (QEMU) in the CCID Card device support. The flaw could
    occur while passing messages via command/response
    packets to and from the host. A privileged user inside
    a guest could use this flaw to crash the QEMU
    process.(CVE-2017-5898)

  - The xhci_kick_epctx function in hw/usb/hcd-xhci.c in
    QEMU (aka Quick Emulator) allows local guest OS
    privileged users to cause a denial of service (infinite
    loop and QEMU process crash) via vectors related to
    control transfer descriptor sequence.(CVE-2017-5973)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1266
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70651d73");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6778");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-img-2.8.1-30.100",
        "qemu-kvm-2.8.1-30.100",
        "qemu-kvm-common-2.8.1-30.100",
        "qemu-kvm-tools-2.8.1-30.100"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-kvm");
}
