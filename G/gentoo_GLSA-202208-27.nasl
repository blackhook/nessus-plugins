#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-27.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164115);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id(
    "CVE-2020-15859",
    "CVE-2020-15863",
    "CVE-2020-16092",
    "CVE-2020-35504",
    "CVE-2020-35505",
    "CVE-2020-35506",
    "CVE-2020-35517",
    "CVE-2021-3409",
    "CVE-2021-3416",
    "CVE-2021-3527",
    "CVE-2021-3544",
    "CVE-2021-3545",
    "CVE-2021-3546",
    "CVE-2021-3582",
    "CVE-2021-3607",
    "CVE-2021-3608",
    "CVE-2021-3611",
    "CVE-2021-3682",
    "CVE-2021-3713",
    "CVE-2021-3748",
    "CVE-2021-3750",
    "CVE-2021-3929",
    "CVE-2021-3930",
    "CVE-2021-3947",
    "CVE-2021-4145",
    "CVE-2021-4158",
    "CVE-2021-4206",
    "CVE-2021-4207",
    "CVE-2021-20203",
    "CVE-2021-20257",
    "CVE-2021-20263",
    "CVE-2022-0358",
    "CVE-2022-26353",
    "CVE-2022-26354"
  );
  script_xref(name:"IAVB", value:"2022-B-0051-S");

  script_name(english:"GLSA-202208-27 : QEMU: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-27 (QEMU: Multiple Vulnerabilities)

  - QEMU 4.2.0 has a use-after-free in hw/net/e1000e_core.c because a guest OS user can trigger an e1000e
    packet with the data's address set to the e1000e's MMIO address. (CVE-2020-15859)

  - hw/net/xgmac.c in the XGMAC Ethernet controller in QEMU before 07-20-2020 has a buffer overflow. This
    occurs during packet transmission and affects the highbank and midway emulated machines. A guest user or
    process could use this flaw to crash the QEMU process on the host, resulting in a denial of service or
    potential privileged code execution. This was fixed in commit 5519724a13664b43e225ca05351c60b4468e4555.
    (CVE-2020-15863)

  - In QEMU through 5.0.0, an assertion failure can occur in the network packet processing. This issue affects
    the e1000e and vmxnet3 network devices. A malicious guest user/process could use this flaw to abort the
    QEMU process on the host, resulting in a denial of service condition in net_tx_pkt_add_raw_fragment in
    hw/net/net_tx_pkt.c. (CVE-2020-16092)

  - A NULL pointer dereference flaw was found in the SCSI emulation support of QEMU in versions before 6.0.0.
    This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is to system availability. (CVE-2020-35504)

  - A NULL pointer dereference flaw was found in the am53c974 SCSI host bus adapter emulation of QEMU in
    versions before 6.0.0. This issue occurs while handling the 'Information Transfer' command. This flaw
    allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service.
    The highest threat from this vulnerability is to system availability. (CVE-2020-35505)

  - A use-after-free vulnerability was found in the am53c974 SCSI host bus adapter emulation of QEMU in
    versions before 6.0.0 during the handling of the 'Information Transfer' command (CMD_TI). This flaw allows
    a privileged guest user to crash the QEMU process on the host, resulting in a denial of service or
    potential code execution with the privileges of the QEMU process. (CVE-2020-35506)

  - A flaw was found in qemu. A host privilege escalation issue was found in the virtio-fs shared file system
    daemon where a privileged guest user is able to create a device special file in the shared directory and
    use it to r/w access host devices. (CVE-2020-35517)

  - An integer overflow issue was found in the vmxnet3 NIC emulator of the QEMU for versions up to v5.2.0. It
    may occur if a guest was to supply invalid values for rx/tx queue size or other NIC parameters. A
    privileged guest user may use this flaw to crash the QEMU process on the host resulting in DoS scenario.
    (CVE-2021-20203)

  - An infinite loop flaw was found in the e1000 NIC emulator of the QEMU. This issue occurs while processing
    transmits (tx) descriptors in process_tx_desc if various descriptor fields are initialized with invalid
    values. This flaw allows a guest to consume CPU cycles on the host, resulting in a denial of service. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20257)

  - A flaw was found in the virtio-fs shared file system daemon (virtiofsd) of QEMU. The new 'xattrmap' option
    may cause the 'security.capability' xattr in the guest to not drop on file write, potentially leading to a
    modified, privileged executable in the guest. In rare circumstances, this flaw could be used by a
    malicious user to elevate their privileges within the guest. (CVE-2021-20263)

  - The patch for CVE-2020-17380/CVE-2020-25085 was found to be ineffective, thus making QEMU vulnerable to
    the out-of-bounds read/write access issues previously found in the SDHCI controller emulation code. This
    flaw allows a malicious privileged guest to crash the QEMU process on the host, resulting in a denial of
    service or potential code execution. QEMU up to (including) 5.2.0 is affected by this. (CVE-2021-3409)

  - A potential stack overflow via infinite loop issue was found in various NIC emulators of QEMU in versions
    up to and including 5.2.0. The issue occurs in loopback mode of a NIC wherein reentrant DMA checks get
    bypassed. A guest user/process may use this flaw to consume CPU cycles or crash the QEMU process on the
    host resulting in DoS scenario. (CVE-2021-3416)

  - A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a
    single, large transfer request, to reduce the overhead and improve performance. The combined size of the
    bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper
    validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the
    array length and cause the QEMU process to perform an excessive allocation on the stack, resulting in a
    denial of service. (CVE-2021-3527)

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

  - A stack overflow vulnerability was found in the Intel HD Audio device (intel-hda) of QEMU. A malicious
    guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service
    condition. The highest threat from this vulnerability is to system availability. This flaw affects QEMU
    versions prior to 7.0.0. (CVE-2021-3611)

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

  - A DMA reentrancy issue was found in the USB EHCI controller emulation of QEMU. EHCI does not verify if the
    Buffer Pointer overlaps with its MMIO region when it transfers the USB packets. Crafted content may be
    written to the controller's registers and trigger undesirable actions (such as reset) while the device is
    still transferring packets. This can ultimately lead to a use-after-free issue. A malicious guest could
    use this flaw to crash the QEMU process on the host, resulting in a denial of service condition, or
    potentially execute arbitrary code within the context of the QEMU process on the host. This flaw affects
    QEMU versions before 7.0.0. (CVE-2021-3750)

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - A stack-buffer-overflow was found in QEMU in the NVME component. The flaw lies in nvme_changed_nslist()
    where a malicious guest controlling certain input can read out of bounds memory. A malicious user could
    use this flaw leading to disclosure of sensitive information. (CVE-2021-3947)

  - A NULL pointer dereference issue was found in the block mirror layer of QEMU in versions prior to 6.2.0.
    The `self` pointer is dereferenced in mirror_wait_on_conflicts() without ensuring that it's not NULL. A
    malicious unprivileged user within the guest could use this flaw to crash the QEMU process on the host
    when writing data reaches the threshold of mirroring node. (CVE-2021-4145)

  - A flaw was found in the QXL display device emulation in QEMU. An integer overflow in the cursor_alloc()
    function can lead to the allocation of a small cursor object followed by a subsequent heap-based buffer
    overflow. This flaw allows a malicious privileged guest user to crash the QEMU process on the host or
    potentially execute arbitrary code within the context of the QEMU process. (CVE-2021-4206)

  - A flaw was found in the QXL display device emulation in QEMU. A double fetch of guest controlled values
    `cursor->header.width` and `cursor->header.height` can lead to the allocation of a small cursor object
    followed by a subsequent heap-based buffer overflow. A malicious privileged guest user could use this flaw
    to crash the QEMU process on the host or potentially execute arbitrary code within the context of the QEMU
    process. (CVE-2021-4207)

  - A flaw was found in the virtio-net device of QEMU. This flaw was inadvertently introduced with the fix for
    CVE-2021-3748, which forgot to unmap the cached virtqueue elements on error, leading to memory leakage and
    other unexpected results. Affected QEMU version: 6.2.0. (CVE-2022-26353)

  - A flaw was found in the vhost-vsock device of QEMU. In case of error, an invalid element was not detached
    from the virtqueue before freeing its memory, leading to memory leakage and other unexpected results.
    Affected QEMU versions <= 6.2.0. (CVE-2022-26354)

  -  Please review the referenced CVE identifiers for details.  (CVE-2021-3929)

  - QEMU: NULL pointer dereference in pci_write() in hw/acpi/pcihp.c (CVE-2021-4158)

  - QEMU: virtiofsd: potential privilege escalation via CVE-2018-13405 (CVE-2022-0358)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-27");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=733448");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=736605");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=773220");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=775713");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=780816");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=792624");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807055");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=810544");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=820743");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835607");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=839762");
  script_set_attribute(attribute:"solution", value:
"All QEMU users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-emulation/qemu-7.0.0");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3748");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "app-emulation/qemu",
    'unaffected' : make_list("ge 7.0.0"),
    'vulnerable' : make_list("lt 7.0.0")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "QEMU");
}
