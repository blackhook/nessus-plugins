#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151333);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-17380",
    "CVE-2020-25084",
    "CVE-2020-25085",
    "CVE-2020-25625",
    "CVE-2020-27617",
    "CVE-2020-28916",
    "CVE-2021-3409",
    "CVE-2021-3416"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : qemu-kvm (EulerOS-SA-2021-2125)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in QEMU. A heap-based buffer overflow
    vulnerability was found in the SDHCI device emulation
    support allowing a guest user or process to crash the
    QEMU process on the host resulting in a denial of
    service condition, or potentially execute arbitrary
    code with privileges of the QEMU process on the host.
    The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-17380)

  - A flaw was found in QEMU. An out-of-bounds read/write
    access issue was found in the SDHCI Controller emulator
    of QEMU. It may occur while doing multi block SDMA, if
    transfer block size exceeds the
    's->fifo_buffer[s->buf_maxsz]' size which would leave
    the current element pointer 's->data_count' pointing
    out of bounds. This would lead the subsequent DMA r/w
    operation to an OOB access issue where a guest
    user/process may use this flaw to crash the QEMU
    process resulting in DoS scenario. The highest threat
    from this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-25085)

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

  - A potential stack overflow via infinite loop issue was
    found in various NIC emulators of QEMU. The issue
    occurs in loopback mode of a NIC wherein reentrant DMA
    checks get bypassed. A guest user/process may use this
    flaw to consume CPU cycles or crash the QEMU process on
    the host resulting in DoS scenario.(CVE-2021-3416)

  - An infinite loop flaw was found in the USB OHCI
    controller emulator of QEMU. This flaw occurs while
    servicing OHCI isochronous transfer descriptors (TD) in
    the ohci_service_iso_td routine, as it retires a TD if
    it has passed its time frame. It does not check if the
    TD was already processed and holds an error code in
    TD_CC. This issue may happen if the TD list has a loop.
    This flaw allows a guest user or process to consume CPU
    cycles on the host, resulting in a denial of
    service.(CVE-2020-25625)

  - An infinite loop flaw was found in the e1000e device
    emulator in QEMU. This issue could occur while
    receiving packets via the
    e1000e_write_packet_to_guest() routine, if the
    receive(RX) descriptor has a NULL buffer address. This
    flaw allows a privileged guest user to cause a denial
    of service. The highest threat from this vulnerability
    is to system availability.(CVE-2020-28916)

  - An assert(3) failure flaw was found in the networking
    helper functions of QEMU. This vulnerability can occur
    in the eth_get_gso_type() routine if a packet does not
    have a valid networking L3 protocol (ex. IPv4, IPv6)
    value. This flaw allows a guest user to crash the QEMU
    process on the host, resulting in a denial of
    service.(CVE-2020-27617)

  - A use-after-free flaw was found in the USB(xHCI/eHCI)
    controller emulators of QEMU. This flaw occurs while
    setting up the USB packet as a usb_packet_map() routine
    and returns an error that was not checked. This flaw
    allows a guest user or process to crash the QEMU
    process, resulting in a denial of
    service.(CVE-2020-25084)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2125
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2eed6d5");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3409");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17380");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-img-2.8.1-30.137",
        "qemu-kvm-2.8.1-30.137",
        "qemu-kvm-common-2.8.1-30.137",
        "qemu-kvm-tools-2.8.1-30.137"];

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
