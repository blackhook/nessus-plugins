#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159876);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_cve_id(
    "CVE-2019-12067",
    "CVE-2020-15859",
    "CVE-2020-25084",
    "CVE-2020-25742",
    "CVE-2020-25743",
    "CVE-2020-35504",
    "CVE-2020-35505",
    "CVE-2021-3544",
    "CVE-2021-3545",
    "CVE-2021-3546",
    "CVE-2021-3682",
    "CVE-2021-3748",
    "CVE-2021-20196",
    "CVE-2021-20203",
    "CVE-2021-20221",
    "CVE-2021-20255"
  );
  script_xref(name:"IAVB", value:"2020-B-0041-S");
  script_xref(name:"IAVB", value:"2020-B-0063-S");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"EulerOS Virtualization 2.10.0 : qemu (EulerOS-SA-2022-1418)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - The ahci_commit_buf function in ide/ahci.c in QEMU allows attackers to cause a denial of service (NULL
    dereference) when the command header 'ad->cur_cmd' is null. (CVE-2019-12067)

  - QEMU 4.2.0 has a use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e
    packet with the data's address set to the e1000e's MMIO address. (CVE-2020-15859)

  - QEMU 5.0.0 has a use-after-free in hw/usb/hcd-xhci.c because the usb_packet_map return value is not
    checked. (CVE-2020-25084)

  - pci_change_irq_level in hw/pci/pci.c in QEMU before 5.1.1 has a NULL pointer dereference because
    pci_get_bus() might not return a valid pointer. (CVE-2020-25742)

  - hw/ide/pci.c in QEMU before 5.1.1 can trigger a NULL pointer dereference because it lacks a pointer check
    before an ide_cancel_dma_sync call. (CVE-2020-25743)

  - A NULL pointer dereference flaw was found in the SCSI emulation support of QEMU in versions before 6.0.0.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2020-35504)

  - A NULL pointer dereference flaw was found in the am53c974 SCSI host bus adapter emulation of QEMU in
    versions before 6.0.0. This issue occurs while handling the 'Information Transfer' command. This flaw
    allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service.
    The highest threat from this vulnerability is to system availability. (CVE-2020-35505)

  - A NULL pointer dereference flaw was found in the floppy disk emulator of QEMU. This issue occurs while
    processing read/write ioport commands if the selected floppy drive is not initialized with a block device.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2021-20196)

  - An integer overflow issue was found in the vmxnet3 NIC emulator of the QEMU for versions up to v5.2.0. It
    may occur if a guest was to supply invalid values for rx/tx queue size or other NIC parameters. A
    privileged guest user may use this flaw to crash the QEMU process on the host resulting in DoS scenario.
    (CVE-2021-20203)

  - An out-of-bounds heap buffer access issue was found in the ARM Generic Interrupt Controller emulator of
    QEMU up to and including qemu 4.2.0on aarch64 platform. The issue occurs because while writing an
    interrupt ID to the controller memory area, it is not masked to be 4 bits wide. It may lead to the said
    issue while updating controller state fields and their subsequent processing. A privileged guest user may
    use this flaw to crash the QEMU process on the host resulting in DoS scenario. (CVE-2021-20221)

  - A stack overflow via an infinite recursion vulnerability was found in the eepro100 i8255x device emulator
    of QEMU. This issue occurs while processing controller commands due to a DMA reentry issue. This flaw
    allows a guest user or process to consume CPU cycles or crash the QEMU process on the host, resulting in a
    denial of service. The highest threat from this vulnerability is to system availability. (CVE-2021-20255)

  - Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions
    up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-
    gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime. (CVE-2021-3544)

  - An information disclosure vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of
    QEMU in versions up to and including 6.0. The flaw exists in virgl_cmd_get_capset_info() in contrib/vhost-
    user-gpu/virgl.c and could occur due to the read of uninitialized memory. A malicious guest could exploit
    this issue to leak memory from the host. (CVE-2021-3545)

  - An out-of-bounds write vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of
    QEMU in versions up to and including 6.0. The flaw occurs while processing the 'VIRTIO_GPU_CMD_GET_CAPSET'
    command from the guest. It could allow a privileged guest user to crash the QEMU process on the host,
    resulting in a denial of service condition, or potential code execution with the privileges of the QEMU
    process. (CVE-2021-3546)

  - A flaw was found in the USB redirector device emulation of QEMU in versions prior to 6.1.0-rc2. It occurs
    when dropping packets during a bulk transfer from a SPICE client due to the packet queue being full. A
    malicious SPICE client could use this flaw to make QEMU call free() with faked heap chunk metadata,
    resulting in a crash of QEMU or potential code execution with the privileges of the QEMU process on the
    host. (CVE-2021-3682)

  - A use-after-free vulnerability was found in the virtio-net device of QEMU. It could occur when the
    descriptor's address belongs to the non direct access region, due to num_buffers being set after the
    virtqueue elem has been unmapped. A malicious guest could use this flaw to crash QEMU, resulting in a
    denial of service condition, or potentially execute code on the host with the privileges of the QEMU
    process. (CVE-2021-3748)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1418
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0edfba8e");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3748");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.10.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.10.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.10.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "qemu-4.1.0-2.10.0.3.427",
  "qemu-img-4.1.0-2.10.0.3.427"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
