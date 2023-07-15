#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176798);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/07");

  script_cve_id(
    "CVE-2020-14394",
    "CVE-2021-3507",
    "CVE-2021-3611",
    "CVE-2021-3750",
    "CVE-2021-4158",
    "CVE-2021-4206",
    "CVE-2021-4207",
    "CVE-2022-0216",
    "CVE-2022-0358",
    "CVE-2022-3165",
    "CVE-2022-3872",
    "CVE-2022-4144",
    "CVE-2022-26353",
    "CVE-2022-26354",
    "CVE-2022-35414",
    "CVE-2023-0330"
  );

  script_name(english:"EulerOS Virtualization 2.11.0 : qemu (EulerOS-SA-2023-2134)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - An infinite loop flaw was found in the USB xHCI controller emulation of QEMU while computing the length of
    the Transfer Request Block (TRB) Ring. This flaw allows a privileged guest user to hang the QEMU process
    on the host, resulting in a denial of service. (CVE-2020-14394)

  - A heap buffer overflow was found in the floppy disk emulator of QEMU up to 6.0.0 (including). It could
    occur in fdctrl_transfer_handler() in hw/block/fdc.c while processing DMA read data transfers from the
    floppy drive to the guest system. A privileged guest user could use this flaw to crash the QEMU process on
    the host resulting in DoS scenario, or potential information leakage from the host memory. (CVE-2021-3507)

  - A stack overflow vulnerability was found in the Intel HD Audio device (intel-hda) of QEMU. A malicious
    guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service
    condition. The highest threat from this vulnerability is to system availability. This flaw affects QEMU
    versions prior to 7.0.0. (CVE-2021-3611)

  - A DMA reentrancy issue was found in the USB EHCI controller emulation of QEMU. EHCI does not verify if the
    Buffer Pointer overlaps with its MMIO region when it transfers the USB packets. Crafted content may be
    written to the controller's registers and trigger undesirable actions (such as reset) while the device is
    still transferring packets. This can ultimately lead to a use-after-free issue. A malicious guest could
    use this flaw to crash the QEMU process on the host, resulting in a denial of service condition, or
    potentially execute arbitrary code within the context of the QEMU process on the host. This flaw affects
    QEMU versions before 7.0.0. (CVE-2021-3750)

  - A NULL pointer dereference issue was found in the ACPI code of QEMU. A malicious, privileged user within
    the guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service
    condition. (CVE-2021-4158)

  - A flaw was found in the QXL display device emulation in QEMU. An integer overflow in the cursor_alloc()
    function can lead to the allocation of a small cursor object followed by a subsequent heap-based buffer
    overflow. This flaw allows a malicious privileged guest user to crash the QEMU process on the host or
    potentially execute arbitrary code within the context of the QEMU process. (CVE-2021-4206)

  - A flaw was found in the QXL display device emulation in QEMU. A double fetch of guest controlled values
    `cursor->header.width` and `cursor->header.height` can lead to the allocation of a small cursor object
    followed by a subsequent heap-based buffer overflow. A malicious privileged guest user could use this flaw
    to crash the QEMU process on the host or potentially execute arbitrary code within the context of the QEMU
    process. (CVE-2021-4207)

  - A use-after-free vulnerability was found in the LSI53C895A SCSI Host Bus Adapter emulation of QEMU. The
    flaw occurs while processing repeated messages to cancel the current SCSI request via the lsi_do_msgout
    function. This flaw allows a malicious privileged user within the guest to crash the QEMU process on the
    host, resulting in a denial of service. (CVE-2022-0216)

  - A flaw was found in the QEMU virtio-fs shared file system daemon (virtiofsd) implementation. This flaw is
    strictly related to CVE-2018-13405. A local guest user can create files in the directories shared by
    virtio-fs with unintended group ownership in a scenario where a directory is SGID to a certain group and
    is writable by a user who is not a member of the group. This could allow a malicious unprivileged user
    inside the guest to gain access to resources accessible to the root group, potentially escalating their
    privileges within the guest. A malicious local user in the host might also leverage this unexpected
    executable file created by the guest to escalate their privileges on the host system. (CVE-2022-0358)

  - A flaw was found in the virtio-net device of QEMU. This flaw was inadvertently introduced with the fix for
    CVE-2021-3748, which forgot to unmap the cached virtqueue elements on error, leading to memory leakage and
    other unexpected results. Affected QEMU version: 6.2.0. (CVE-2022-26353)

  - A flaw was found in the vhost-vsock device of QEMU. In case of error, an invalid element was not detached
    from the virtqueue before freeing its memory, leading to memory leakage and other unexpected results.
    Affected QEMU versions <= 6.2.0. (CVE-2022-26354)

  - An integer underflow issue was found in the QEMU VNC server while processing ClientCutText messages in the
    extended format. A malicious client could use this flaw to make QEMU unresponsive by sending a specially
    crafted payload message, resulting in a denial of service. (CVE-2022-3165)

  - ** DISPUTED ** softmmu/physmem.c in QEMU through 7.0.0 can perform an uninitialized read on the
    translate_fail path, leading to an io_readx or io_writex crash. NOTE: a third party states that the Non-
    virtualization Use Case in the qemu.org reference applies here, i.e., 'Bugs affecting the non-
    virtualization use case are not considered security bugs at this time.' (CVE-2022-35414)

  - An off-by-one read/write issue was found in the SDHCI device of QEMU. It occurs when reading/writing the
    Buffer Data Port Register in sdhci_read_dataport and sdhci_write_dataport, respectively, if data_count ==
    block_size. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a
    denial of service condition. (CVE-2022-3872)

  - An out-of-bounds read flaw was found in the QXL display device emulation in QEMU. The qxl_phys2virt()
    function does not check the size of the structure pointed to by the guest physical address, potentially
    reading past the end of the bar space into adjacent pages. A malicious guest user could use this flaw to
    crash the QEMU process on the host causing a denial of service condition. (CVE-2022-4144)

  - A vulnerability in the lsi53c895a device affects the latest version of qemu. A DMA-MMIO reentrancy problem
    may lead to memory corruption bugs like stack overflow or use-after-free. (CVE-2023-0330)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2134
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b70adfc6");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35414");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.11.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.11.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "qemu-6.2.0-391"
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
