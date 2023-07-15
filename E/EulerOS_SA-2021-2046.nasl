#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151231);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2019-20382",
    "CVE-2020-13754",
    "CVE-2020-25085",
    "CVE-2020-25742",
    "CVE-2020-25743",
    "CVE-2021-3392",
    "CVE-2021-3409",
    "CVE-2021-3416"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.6 : qemu-kvm (EulerOS-SA-2021-2046)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - An out-of-bounds access flaw was found in the Message
    Signalled Interrupt (MSI-X) device support of QEMU.
    This issue occurs while performing MSI-X mmio
    operations when a guest sent address goes beyond the
    mmio region. A guest user or process may use this flaw
    to crash the QEMU process resulting in a denial of
    service.(CVE-2020-13754)

  - hw/ide/pci.c in QEMU before 5.1.1 can trigger a NULL
    pointer dereference because it lacks a pointer check
    before an ide_cancel_dma_sync call.(CVE-2020-25743)

  - pci_change_irq_level in hw/pci/pci.c in QEMU before
    5.1.1 has a NULL pointer dereference because
    pci_get_bus() might not return a valid
    pointer.(CVE-2020-25742)

  - QEMU 5.0.0 has a heap-based Buffer Overflow in
    flatview_read_continue in exec.c because hw/sd/sdhci.c
    mishandles a write operation in the SDHC_BLKSIZE
    case.(CVE-2020-25085)

  - The patch for CVE-2020-17380 and CVE-2020-25085, both
    involving a heap buffer overflow in the SDHCI
    controller emulation code of QEMU, was found to be
    incomplete. A malicious privileged guest could
    reproduce the same issues with specially crafted input,
    inducing a bogus transfer and subsequent out-of-bounds
    read/write access in sdhci_do_adma() or
    sdhci_sdma_transfer_multi_blocks(). CVE-2021-3409 was
    assigned to facilitate the tracking and backporting of
    the new patch.(CVE-2021-3409)

  - A use-after-free flaw was found in the MegaRAID
    emulator of QEMU. This issue occurs while processing
    SCSI I/O requests in the case of an error
    mptsas_free_request() that does not dequeue the request
    object 'req' from a pending requests queue. This flaw
    allows a privileged guest user to crash the QEMU
    process on the host, resulting in a denial of
    service.(CVE-2021-3392)

  - A potential stack overflow via infinite loop issue was
    found in various NIC emulators of QEMU. The issue
    occurs in loopback mode of a NIC wherein reentrant DMA
    checks get bypassed. A guest user/process may use this
    flaw to consume CPU cycles or crash the QEMU process on
    the host resulting in DoS scenario.(CVE-2021-3416)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2046
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cacf841");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3409");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-gpu-specs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-gpu-specs-2.8.1-30.211",
        "qemu-guest-agent-2.8.1-30.211",
        "qemu-img-2.8.1-30.211",
        "qemu-kvm-2.8.1-30.211",
        "qemu-kvm-common-2.8.1-30.211",
        "qemu-kvm-tools-2.8.1-30.211",
        "qemu-seabios-2.8.1-30.211"];

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
