#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140317);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id(
    "CVE-2017-7377",
    "CVE-2019-20382",
    "CVE-2020-13253",
    "CVE-2020-13361",
    "CVE-2020-13362",
    "CVE-2020-13659",
    "CVE-2020-13765",
    "CVE-2020-13791",
    "CVE-2020-14364",
    "CVE-2020-15863",
    "CVE-2020-16092",
    "CVE-2020-1983"
  );
  script_xref(name:"IAVB", value:"2020-B-0063-S");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : qemu-kvm (EulerOS-SA-2020-1947)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - QEMU: reachable assertion failure in
    net_tx_pkt_add_raw_fragment() in hw/net/net_tx_pkt.c
    (CVE-2020-16092)

  - An out-of-bounds read/write access flaw was found in
    the USB emulator of the QEMU. This issue occurs while
    processing USB packets from a guest when USBDevice
    'setup_len' exceeds its 'data_buf[4096]' in the
    do_token_in, do_token_out routines. This flaw allows a
    guest user to crash the QEMU process, resulting in a
    denial of service, or the potential execution of
    arbitrary code with the privileges of the QEMU process
    on the host.(CVE-2020-14364)

  - A use after free vulnerability in ip_reass() in
    ip_input.c of libslirp 4.2.0 and prior releases allows
    crafted packets to cause a denial of
    service.(CVE-2020-1983)

  - hw/net/xgmac.c in the XGMAC Ethernet controller in QEMU
    before 07-20-2020 has a buffer overflow. This occurs
    during packet transmission and affects the highbank and
    midway emulated machines. A guest user or process could
    use this flaw to crash the QEMU process on the host,
    resulting in a denial of service or potential
    privileged code execution. This was fixed in commit
    5519724a13664b43e225ca05351c60b4468e4555.(CVE-2020-1586
    3)

  - The (1) v9fs_create and (2) v9fs_lcreate functions in
    hw/9pfs/9p.c in QEMU (aka Quick Emulator) allow local
    guest OS privileged users to cause a denial of service
    (file descriptor or memory consumption) via vectors
    related to an already in-use fid.(CVE-2017-7377)

  - QEMU 4.1.0 has a memory leak in zrle_compress_data in
    ui/vnc-enc-zrle.c during a VNC disconnect operation
    because libz is misused, resulting in a situation where
    memory allocated in deflateInit2 is not freed in
    deflateEnd.(CVE-2019-20382)

  - sd_wp_addr in hw/sd/sd.c in QEMU 4.2.0 uses an
    unvalidated address, which leads to an out-of-bounds
    read during sdhci_write() operations. A guest OS user
    can crash the QEMU process.(CVE-2020-13253)

  - In QEMU 5.0.0 and earlier, es1370_transfer_audio in
    hw/audio/es1370.c does not properly validate the frame
    count, which allows guest OS users to trigger an
    out-of-bounds access during an es1370_write()
    operation.(CVE-2020-13361)

  - In QEMU 5.0.0 and earlier, megasas_lookup_frame in
    hw/scsi/megasas.c has an out-of-bounds read via a
    crafted reply_queue_head field from a guest OS
    user.(CVE-2020-13362)

  - address_space_map in exec.c in QEMU 4.2.0 can trigger a
    NULL pointer dereference related to
    BounceBuffer.(CVE-2020-13659)

  - hw/pci/pci.c in QEMU 4.2.0 allows guest OS users to
    trigger an out-of-bounds access by providing an address
    near the end of the PCI configuration
    space.(CVE-2020-13791)

  - rom_copy() in hw/core/loader.c in QEMU 4.1.0 does not
    validate the relationship between two addresses, which
    allows attackers to trigger an invalid memory copy
    operation.(CVE-2020-13765)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1947
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83494b72");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13765");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

pkgs = ["qemu-img-2.8.1-30.123",
        "qemu-kvm-2.8.1-30.123",
        "qemu-kvm-common-2.8.1-30.123",
        "qemu-kvm-tools-2.8.1-30.123"];

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
