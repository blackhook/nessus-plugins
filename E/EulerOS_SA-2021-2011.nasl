#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151162);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-13754",
    "CVE-2020-13791",
    "CVE-2020-17380",
    "CVE-2020-25085",
    "CVE-2020-25625",
    "CVE-2020-27617",
    "CVE-2020-28916",
    "CVE-2021-3409",
    "CVE-2021-3416"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : qemu-kvm (EulerOS-SA-2021-2011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A potential stack overflow via infinite loop issue was
    found in various NIC emulators of QEMU in versions up
    to and including 5.2.0. The issue occurs in loopback
    mode of a NIC wherein reentrant DMA checks get
    bypassed. A guest user/process may use this flaw to
    consume CPU cycles or crash the QEMU process on the
    host resulting in DoS scenario.(CVE-2021-34161)

  - hw/pci/pci.c in QEMU 4.2.0 allows guest OS users to
    trigger an out-of-bounds access by providing an address
    near the end of the PCI configuration
    space.(CVE-2020-13791)

  - hw/pci/msix.c in QEMU 4.2.0 allows guest OS users to
    trigger an out-of-bounds access via a crafted address
    in an msi-x mmio operation.(CVE-2020-13754)

  - A heap-based buffer overflow was found in QEMU through
    5.0.0 in the SDHCI device emulation support. It could
    occur while doing a multi block SDMA transfer via the
    sdhci_sdma_transfer_multi_blocks() routine in
    hw/sd/sdhci.c. A guest user or process could use this
    flaw to crash the QEMU process on the host, resulting
    in a denial of service condition, or potentially
    execute arbitrary code with privileges of the QEMU
    process on the host. (CVE-2020-17380)

  - QEMU 5.0.0 has a heap-based Buffer Overflow in
    flatview_read_continue in exec.c because hw/sd/sdhci.c
    mishandles a write operation in the SDHC_BLKSIZE case.
    (CVE-2020-25085)

  - The patch for CVE-2020-17380/CVE-2020-25085 was found
    to be ineffective, thus making QEMU vulnerable to the
    out-of-bounds read/write access issues previously found
    in the SDHCI controller emulation code. This flaw
    allows a malicious privileged guest to crash the QEMU
    process on the host, resulting in a denial of service
    or potential code execution. QEMU up to (including)
    5.2.0 is affected by this. (CVE-2021-3409)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7959c880");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-img-2.8.1-30.482",
        "qemu-kvm-2.8.1-30.482",
        "qemu-kvm-common-2.8.1-30.482",
        "qemu-kvm-tools-2.8.1-30.482"];

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
