#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3099. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164678);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/04");

  script_cve_id(
    "CVE-2020-13253",
    "CVE-2020-15469",
    "CVE-2020-15859",
    "CVE-2020-25084",
    "CVE-2020-25085",
    "CVE-2020-25624",
    "CVE-2020-25625",
    "CVE-2020-25723",
    "CVE-2020-27617",
    "CVE-2020-27821",
    "CVE-2020-28916",
    "CVE-2020-29129",
    "CVE-2020-29443",
    "CVE-2020-35504",
    "CVE-2020-35505",
    "CVE-2021-3392",
    "CVE-2021-3416",
    "CVE-2021-3507",
    "CVE-2021-3527",
    "CVE-2021-3582",
    "CVE-2021-3607",
    "CVE-2021-3608",
    "CVE-2021-3682",
    "CVE-2021-3713",
    "CVE-2021-3748",
    "CVE-2021-3930",
    "CVE-2021-4206",
    "CVE-2021-4207",
    "CVE-2021-20181",
    "CVE-2021-20196",
    "CVE-2021-20203",
    "CVE-2021-20221",
    "CVE-2021-20257",
    "CVE-2022-26354",
    "CVE-2022-35414"
  );
  script_xref(name:"IAVB", value:"2020-B-0041-S");
  script_xref(name:"IAVB", value:"2020-B-0063-S");
  script_xref(name:"IAVB", value:"2020-B-0026-S");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"Debian DLA-3099-1 : qemu - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3099 advisory.

  - sd_wp_addr in hw/sd/sd.c in QEMU 4.2.0 uses an unvalidated address, which leads to an out-of-bounds read
    during sdhci_write() operations. A guest OS user can crash the QEMU process. (CVE-2020-13253)

  - In QEMU 4.2.0, a MemoryRegionOps object may lack read/write callback methods, leading to a NULL pointer
    dereference. (CVE-2020-15469)

  - QEMU 4.2.0 has a use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e
    packet with the data's address set to the e1000e's MMIO address. (CVE-2020-15859)

  - QEMU 5.0.0 has a use-after-free in hw/usb/hcd-xhci.c because the usb_packet_map return value is not
    checked. (CVE-2020-25084)

  - QEMU 5.0.0 has a heap-based Buffer Overflow in flatview_read_continue in exec.c because hw/sd/sdhci.c
    mishandles a write operation in the SDHC_BLKSIZE case. (CVE-2020-25085)

  - hw/usb/hcd-ohci.c in QEMU 5.0.0 has a stack-based buffer over-read via values obtained from the host
    controller driver. (CVE-2020-25624)

  - hw/usb/hcd-ohci.c in QEMU 5.0.0 has an infinite loop when a TD list has a loop. (CVE-2020-25625)

  - A reachable assertion issue was found in the USB EHCI emulation code of QEMU. It could occur while
    processing USB requests due to missing handling of DMA memory map failure. A malicious privileged user
    within the guest may abuse this flaw to send bogus USB requests and crash the QEMU process on the host,
    resulting in a denial of service. (CVE-2020-25723)

  - eth_get_gso_type in net/eth.c in QEMU 4.2.1 allows guest OS users to trigger an assertion failure. A guest
    can crash the QEMU process via packet data that lacks a valid Layer 3 protocol. (CVE-2020-27617)

  - A flaw was found in the memory management API of QEMU during the initialization of a memory region cache.
    This issue could lead to an out-of-bounds write access to the MSI-X table while performing MMIO
    operations. A guest user may abuse this flaw to crash the QEMU process on the host, resulting in a denial
    of service. This flaw affects QEMU versions prior to 5.2.0. (CVE-2020-27821)

  - hw/net/e1000e_core.c in QEMU 5.0.0 has an infinite loop via an RX descriptor with a NULL buffer address.
    (CVE-2020-28916)

  - ncsi.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29129)

  - ide_atapi_cmd_reply_end in hw/ide/atapi.c in QEMU 5.1.0 allows out-of-bounds read access because a buffer
    index is not validated. (CVE-2020-29443)

  - A NULL pointer dereference flaw was found in the SCSI emulation support of QEMU in versions before 6.0.0.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2020-35504)

  - A NULL pointer dereference flaw was found in the am53c974 SCSI host bus adapter emulation of QEMU in
    versions before 6.0.0. This issue occurs while handling the 'Information Transfer' command. This flaw
    allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service.
    The highest threat from this vulnerability is to system availability. (CVE-2020-35505)

  - A race condition flaw was found in the 9pfs server implementation of QEMU up to and including 5.2.0. This
    flaw allows a malicious 9p client to cause a use-after-free error, potentially escalating their privileges
    on the system. The highest threat from this vulnerability is to confidentiality, integrity as well as
    system availability. (CVE-2021-20181)

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

  - An infinite loop flaw was found in the e1000 NIC emulator of the QEMU. This issue occurs while processing
    transmits (tx) descriptors in process_tx_desc if various descriptor fields are initialized with invalid
    values. This flaw allows a guest to consume CPU cycles on the host, resulting in a denial of service. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20257)

  - A use-after-free flaw was found in the MegaRAID emulator of QEMU. This issue occurs while processing SCSI
    I/O requests in the case of an error mptsas_free_request() that does not dequeue the request object 'req'
    from a pending requests queue. This flaw allows a privileged guest user to crash the QEMU process on the
    host, resulting in a denial of service. Versions between 2.10.0 and 5.2.0 are potentially affected.
    (CVE-2021-3392)

  - A potential stack overflow via infinite loop issue was found in various NIC emulators of QEMU in versions
    up to and including 5.2.0. The issue occurs in loopback mode of a NIC wherein reentrant DMA checks get
    bypassed. A guest user/process may use this flaw to consume CPU cycles or crash the QEMU process on the
    host resulting in DoS scenario. (CVE-2021-3416)

  - A heap buffer overflow was found in the floppy disk emulator of QEMU up to 6.0.0 (including). It could
    occur in fdctrl_transfer_handler() in hw/block/fdc.c while processing DMA read data transfers from the
    floppy drive to the guest system. A privileged guest user could use this flaw to crash the QEMU process on
    the host resulting in DoS scenario, or potential information leakage from the host memory. (CVE-2021-3507)

  - A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a
    single, large transfer request, to reduce the overhead and improve performance. The combined size of the
    bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper
    validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the
    array length and cause the QEMU process to perform an excessive allocation on the stack, resulting in a
    denial of service. (CVE-2021-3527)

  - A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA device. The issue occurs while
    handling a PVRDMA_CMD_CREATE_MR command due to improper memory remapping (mremap). This flaw allows a
    malicious guest to crash the QEMU process on the host. The highest threat from this vulnerability is to
    system availability. (CVE-2021-3582)

  - An integer overflow was found in the QEMU implementation of VMWare's paravirtual RDMA device in versions
    prior to 6.1.0. The issue occurs while handling a PVRDMA_REG_DSRHIGH write from the guest due to
    improper input validation. This flaw allows a privileged guest user to make QEMU allocate a large amount
    of memory, resulting in a denial of service. The highest threat from this vulnerability is to system
    availability. (CVE-2021-3607)

  - A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA device in versions prior to
    6.1.0. The issue occurs while handling a PVRDMA_REG_DSRHIGH write from the guest and may result in a
    crash of QEMU or cause undefined behavior due to the access of an uninitialized pointer. The highest
    threat from this vulnerability is to system availability. (CVE-2021-3608)

  - A flaw was found in the USB redirector device emulation of QEMU in versions prior to 6.1.0-rc2. It occurs
    when dropping packets during a bulk transfer from a SPICE client due to the packet queue being full. A
    malicious SPICE client could use this flaw to make QEMU call free() with faked heap chunk metadata,
    resulting in a crash of QEMU or potential code execution with the privileges of the QEMU process on the
    host. (CVE-2021-3682)

  - An out-of-bounds write flaw was found in the UAS (USB Attached SCSI) device emulation of QEMU in versions
    prior to 6.2.0-rc0. The device uses the guest supplied stream number unchecked, which can lead to out-of-
    bounds access to the UASDevice->data3 and UASDevice->status3 fields. A malicious guest user could use this
    flaw to crash QEMU or potentially achieve code execution with the privileges of the QEMU process on the
    host. (CVE-2021-3713)

  - A use-after-free vulnerability was found in the virtio-net device of QEMU. It could occur when the
    descriptor's address belongs to the non direct access region, due to num_buffers being set after the
    virtqueue elem has been unmapped. A malicious guest could use this flaw to crash QEMU, resulting in a
    denial of service condition, or potentially execute code on the host with the privileges of the QEMU
    process. (CVE-2021-3748)

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - A flaw was found in the QXL display device emulation in QEMU. An integer overflow in the cursor_alloc()
    function can lead to the allocation of a small cursor object followed by a subsequent heap-based buffer
    overflow. This flaw allows a malicious privileged guest user to crash the QEMU process on the host or
    potentially execute arbitrary code within the context of the QEMU process. (CVE-2021-4206)

  - A flaw was found in the QXL display device emulation in QEMU. A double fetch of guest controlled values
    `cursor->header.width` and `cursor->header.height` can lead to the allocation of a small cursor object
    followed by a subsequent heap-based buffer overflow. A malicious privileged guest user could use this flaw
    to crash the QEMU process on the host or potentially execute arbitrary code within the context of the QEMU
    process. (CVE-2021-4207)

  - A flaw was found in the vhost-vsock device of QEMU. In case of error, an invalid element was not detached
    from the virtqueue before freeing its memory, leading to memory leakage and other unexpected results.
    Affected QEMU versions <= 6.2.0. (CVE-2022-26354)

  - softmmu/physmem.c in QEMU through 7.0.0 can perform an uninitialized read on the translate_fail path,
    leading to an io_readx or io_writex crash. (CVE-2022-35414)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/qemu");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-13253");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-15469");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-15859");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25084");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25624");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25625");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27821");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29129");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29443");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35504");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35505");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20196");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20203");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20221");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20257");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3392");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3416");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3507");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3527");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3582");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3607");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3682");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3713");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3930");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4207");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26354");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-35414");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/qemu");
  script_set_attribute(attribute:"solution", value:
"Upgrade the qemu packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3748");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-35414");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'qemu', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-block-extra', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-guest-agent', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-kvm', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-arm', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-common', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-data', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-gui', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-mips', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-misc', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-ppc', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-sparc', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-system-x86', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-user', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-user-binfmt', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-user-static', 'reference': '1:3.1+dfsg-8+deb10u9'},
    {'release': '10.0', 'prefix': 'qemu-utils', 'reference': '1:3.1+dfsg-8+deb10u9'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}
