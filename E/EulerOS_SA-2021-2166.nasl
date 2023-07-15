#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151383);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id(
    "CVE-2016-7907",
    "CVE-2017-10806",
    "CVE-2017-11434",
    "CVE-2017-13711",
    "CVE-2017-8380",
    "CVE-2018-11806",
    "CVE-2018-15746",
    "CVE-2018-17958",
    "CVE-2018-17962",
    "CVE-2018-20815",
    "CVE-2019-12155",
    "CVE-2019-13164",
    "CVE-2019-14378",
    "CVE-2019-9824",
    "CVE-2020-10756",
    "CVE-2020-13765",
    "CVE-2020-14364",
    "CVE-2020-25084",
    "CVE-2020-25625",
    "CVE-2020-25723",
    "CVE-2020-7039",
    "CVE-2020-7211"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : qemu-kvm (EulerOS-SA-2021-2166)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The imx_fec_do_tx function in hw/net/imx_fec.c in QEMU
    (aka Quick Emulator) does not properly limit the buffer
    descriptor count when transmitting packets, which
    allows local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) via
    vectors involving a buffer descriptor with a length of
    0 and crafted values in bd.flags.(CVE-2016-7907)

  - Stack-based buffer overflow in hw/usb/redirect.c in
    QEMU (aka Quick Emulator) allows local guest OS users
    to cause a denial of service (QEMU process crash) via
    vectors related to logging debug
    messages.(CVE-2017-10806)

  - The dhcp_decode function in slirp/bootp.c in QEMU (aka
    Quick Emulator) allows local guest OS users to cause a
    denial of service (out-of-bounds read and QEMU process
    crash) via a crafted DHCP options
    string.(CVE-2017-11434)

  - A use-after-free issue was found in the Slirp
    networking implementation of the Quick emulator (QEMU).
    It occurs when a Socket referenced from multiple
    packets is freed while responding to a message. A
    user/process could use this flaw to crash the QEMU
    process on the host resulting in denial of
    service.(CVE-2017-13711)

  - Buffer overflow in the 'megasas_mmio_write' function in
    Qemu 2.9.0 allows remote attackers to have unspecified
    impact via unknown vectors.(CVE-2017-8380)

  - A heap buffer overflow issue was found in the way SLiRP
    networking back-end in QEMU processes fragmented
    packets. It could occur while reassembling the
    fragmented datagrams of an incoming packet. A
    privileged user/process inside guest could use this
    flaw to crash the QEMU process resulting in DoS or
    potentially leverage it to execute arbitrary code on
    the host with privileges of the QEMU
    process.(CVE-2018-11806)

  - qemu-seccomp.c in QEMU might allow local OS guest users
    to cause a denial of service (guest crash) by
    leveraging mishandling of the seccomp policy for
    threads other than the main thread.(CVE-2018-15746)

  - An integer overflow issue was found in the RTL8139 NIC
    emulation in QEMU. It could occur while receiving
    packets over the network if the size value is greater
    than INT_MAX. Such overflow would lead to stack buffer
    overflow issue. A user inside guest could use this flaw
    to crash the QEMU process, resulting in DoS
    scenario.(CVE-2018-17958)

  - An integer overflow issue was found in the AMD PC-Net
    II NIC emulation in QEMU. It could occur while
    receiving packets, if the size value was greater than
    INT_MAX. Such overflow would lead to stack buffer
    overflow issue. A user inside guest could use this flaw
    to crash the QEMU process resulting in
    DoS.(CVE-2018-17962)

  - A heap buffer overflow issue was found in the
    load_device_tree() function of QEMU, which is invoked
    to load a device tree blob at boot time. It occurs due
    to device tree size manipulation before buffer
    allocation, which could overflow a signed int type. A
    user/process could use this flaw to potentially execute
    arbitrary code on a host system with privileges of the
    QEMU process.(CVE-2018-20815)

  - interface_release_resource in hw/display/qxl.c in QEMU
    3.1.x through 4.0.0 has a NULL pointer
    dereference.(CVE-2019-12155)

  - qemu-bridge-helper.c in QEMU 3.1 and 4.0.0 does not
    ensure that a network interface name (obtained from
    bridge.conf or a --br=bridge option) is limited to the
    IFNAMSIZ size, which can lead to an ACL
    bypass.(CVE-2019-13164)

  - A heap buffer overflow issue was found in the SLiRP
    networking implementation of the QEMU emulator. This
    flaw occurs in the ip_reass() routine while
    reassembling incoming packets if the first fragment is
    bigger than the m->m_dat[] buffer. An attacker could
    use this flaw to crash the QEMU process on the host,
    resulting in a Denial of Service or potentially
    executing arbitrary code with privileges of the QEMU
    process.(CVE-2019-14378)

  - tcp_emu in slirp/tcp_subr.c (aka slirp/src/tcp_subr.c)
    in QEMU 3.0.0 uses uninitialized data in an snprintf
    call, leading to Information disclosure.(CVE-2019-9824)

  - An out-of-bounds read vulnerability was found in the
    SLiRP networking implementation of the QEMU emulator.
    This flaw occurs in the icmp6_send_echoreply() routine
    while replying to an ICMP echo request, also known as
    ping. This flaw allows a malicious guest to leak the
    contents of the host memory, resulting in possible
    information disclosure.(CVE-2020-10756)

  - A heap buffer overflow issue was found in the SLiRP
    networking implementation of the QEMU emulator. This
    flaw occurs in the tcp_emu() routine while emulating
    IRC and other protocols. An attacker could use this
    flaw to crash the QEMU process on the host, resulting
    in a denial of service or potential execution of
    arbitrary code with privileges of the QEMU
    process.(CVE-2020-7039)

  - An out-of-bound write access flaw was found in the way
    QEMU loads ROM contents at boot time. This flaw occurs
    in the rom_copy() routine while loading the contents of
    a 32-bit -kernel image into memory. Running an
    untrusted -kernel image may load contents at arbitrary
    memory locations, potentially leading to code execution
    with the privileges of the QEMU
    process.(CVE-2020-13765)

  - A use-after-free flaw was found in the USB(xHCI/eHCI)
    controller emulators of QEMU. This flaw occurs while
    setting up the USB packet as a usb_packet_map() routine
    and returns an error that was not checked. This flaw
    allows a guest user or process to crash the QEMU
    process, resulting in a denial of
    service.(CVE-2020-25084)

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

  - A reachable assertion issue was found in the USB EHCI
    emulation code of QEMU. It could occur while processing
    USB requests due to missing handling of DMA memory map
    failure. A malicious privileged user within the guest
    may abuse this flaw to send bogus USB requests and
    crash the QEMU process on the host, resulting in a
    denial of service.(CVE-2020-25723)

  - A potential directory traversal issue was found in the
    tftp server of the SLiRP user-mode networking
    implementation used by QEMU. It could occur on a
    Windows host, as it allows the use of both forward
    ('/') and backward slash('\') tokens as separators in a
    file path. A user able to access the tftp server could
    use this flaw to access undue files by using relative
    paths.(CVE-2020-7211)

  - An out-of-bounds read/write access flaw was found in
    the USB emulator of the QEMU in versions before 5.2.0.
    This issue occurs while processing USB packets from a
    guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out
    routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the
    potential execution of arbitrary code with the
    privileges of the QEMU process on the
    host.(CVE-2020-14364)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2166
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3456612");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-gpu-specs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-gpu-specs-2.8.1-30.086",
        "qemu-img-2.8.1-30.086",
        "qemu-kvm-2.8.1-30.086",
        "qemu-kvm-common-2.8.1-30.086",
        "qemu-kvm-tools-2.8.1-30.086",
        "qemu-seabios-2.8.1-30.086"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
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
