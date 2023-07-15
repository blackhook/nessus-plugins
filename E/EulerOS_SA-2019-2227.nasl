#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130689);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2013-4526",
    "CVE-2013-4530",
    "CVE-2013-4539",
    "CVE-2013-4540",
    "CVE-2013-4544",
    "CVE-2015-4037",
    "CVE-2015-5279",
    "CVE-2015-7549",
    "CVE-2016-2538",
    "CVE-2016-2841",
    "CVE-2016-7161",
    "CVE-2016-7908",
    "CVE-2017-18043",
    "CVE-2017-5579",
    "CVE-2017-5667",
    "CVE-2017-5987",
    "CVE-2017-9373",
    "CVE-2017-9374",
    "CVE-2017-9503",
    "CVE-2018-10839",
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-11091",
    "CVE-2019-12155",
    "CVE-2019-6778",
    "CVE-2019-9824"
  );
  script_bugtraq_id(66955, 67483, 74809);
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"EulerOS 2.0 SP5 : qemu-kvm (EulerOS-SA-2019-2227)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu-kvm packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In QEMU 3.0.0, tcp_emu in slirp/tcp_subr.c has a
    heap-based buffer overflow.(CVE-2019-6778)

  - The MSI-X MMIO support in hw/pci/msix.c in QEMU (aka
    Quick Emulator) allows local guest OS privileged users
    to cause a denial of service (NULL pointer dereference
    and QEMU process crash) by leveraging failure to define
    the .write method.(CVE-2015-7549)

  - The ne2000_receive function in the NE2000 NIC emulation
    support (hw/net/ne2000.c) in QEMU before 2.5.1 allows
    local guest OS administrators to cause a denial of
    service (infinite loop and QEMU process crash) via
    crafted values for the PSTART and PSTOP registers,
    involving ring buffer control.(CVE-2016-2841)

  - Memory leak in QEMU (aka Quick Emulator), when built
    with USB EHCI Emulation support, allows local guest OS
    privileged users to cause a denial of service (memory
    consumption) by repeatedly hot-unplugging the
    device.(CVE-2017-9374)

  - Integer overflow in the macro ROUND_UP (n, d) in Quick
    Emulator (Qemu) allows a user to cause a denial of
    service (Qemu process crash).(CVE-2017-18043)

  - Memory leak in the serial_exit_core function in
    hw/char/serial.c in QEMU (aka Quick Emulator) allows
    local guest OS privileged users to cause a denial of
    service (host memory consumption and QEMU process
    crash) via a large number of device unplug
    operations.(CVE-2017-5579)

  - The slirp_smb function in net/slirp.c in QEMU 2.3.0 and
    earlier creates temporary files with predictable names,
    which allows local users to cause a denial of service
    (instantiation failure) by creating /tmp/qemu-smb.*-*
    files before the program.(CVE-2015-4037)

  - The mcf_fec_do_tx function in hw/net/mcf_fec.c in QEMU
    (aka Quick Emulator) does not properly limit the buffer
    descriptor count when transmitting packets, which
    allows local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) via
    vectors involving a buffer descriptor with a length of
    0 and crafted values in bd.flags.(CVE-2016-7908)

  - hw/net/vmxnet3.c in QEMU 2.0.0-rc0, 1.7.1, and earlier
    allows local guest users to cause a denial of service
    or possibly execute arbitrary code via vectors related
    to (1) RX or (2) TX queue numbers or (3) interrupt
    indices. NOTE: some of these details are obtained from
    third party information.(CVE-2013-4544)

  - Multiple integer overflows in the USB Net device
    emulator (hw/usb/dev-network.c) in QEMU before 2.5.1
    allow local guest OS administrators to cause a denial
    of service (QEMU process crash) or obtain sensitive
    host memory information via a remote NDIS control
    message packet that is mishandled in the (1)
    rndis_query_response, (2) rndis_set_response, or (3)
    usb_net_handle_dataout function.(CVE-2016-2538)

  - Qemu emulator <= 3.0.0 built with the NE2000 NIC
    emulation support is vulnerable to an integer overflow,
    which could lead to buffer overflow issue. It could
    occur when receiving packets over the network. A user
    inside guest could use this flaw to crash the Qemu
    process resulting in DoS.(CVE-2018-10839)

  - Memory leak in QEMU (aka Quick Emulator), when built
    with IDE AHCI Emulation support, allows local guest OS
    privileged users to cause a denial of service (memory
    consumption) by repeatedly hot-unplugging the AHCI
    device.(CVE-2017-9373)

  - tcp_emu in slirp/tcp_subr.c (aka slirp/src/tcp_subr.c)
    in QEMU 3.0.0 uses uninitialized data in an snprintf
    call, leading to Information disclosure.(CVE-2019-9824)

  - QEMU (aka Quick Emulator), when built with MegaRAID SAS
    8708EM2 Host Bus Adapter emulation support, allows
    local guest OS privileged users to cause a denial of
    service (NULL pointer dereference and QEMU process
    crash) via vectors involving megasas command
    processing.(CVE-2017-9503)

  - Buffer overflow in hw/ide/ahci.c in QEMU before 1.7.2
    allows remote attackers to cause a denial of service
    and possibly execute arbitrary code via vectors related
    to migrating ports.(CVE-2013-4526)

  - Buffer overflow in hw/ssi/pl022.c in QEMU before 1.7.2
    allows remote attackers to cause a denial of service or
    possibly execute arbitrary code via crafted
    tx_fifo_head and rx_fifo_head values in a savevm
    image.(CVE-2013-4530)

  - Multiple buffer overflows in the tsc210x_load function
    in hw/input/tsc210x.c in QEMU before 1.7.2 might allow
    remote attackers to execute arbitrary code via a
    crafted (1) precision, (2) nextprecision, (3) function,
    or (4) nextfunction value in a savevm
    image.(CVE-2013-4539)

  - Buffer overflow in scoop_gpio_handler_update in QEMU
    before 1.7.2 might allow remote attackers to execute
    arbitrary code via a large (1) prev_level, (2)
    gpio_level, or (3) gpio_dir value in a savevm
    image.(CVE-2013-4540)

  - The sdhci_sdma_transfer_multi_blocks function in
    hw/sd/sdhci.c in QEMU (aka Quick Emulator) allows local
    OS guest privileged users to cause a denial of service
    (infinite loop and QEMU process crash) via vectors
    involving the transfer mode register during multi block
    transfer.(CVE-2017-5987)

  - Microarchitectural Store Buffer Data Sampling (MSBDS):
    Store buffers on some microprocessors utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access. A list of impacted products
    can be found here:
    https://www.intel.com/content/dam/www/public/us/en/docu
    ments/corporate-information/SA00233-microcode-update-gu
    idance_05132019.pdf(CVE-2018-12126)

  - Microarchitectural Load Port Data Sampling (MLPDS):
    Load ports on some microprocessors utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access. A list of impacted products
    can be found here:
    https://www.intel.com/content/dam/www/public/us/en/docu
    ments/corporate-information/SA00233-microcode-update-gu
    idance_05132019.pdf(CVE-2018-12127)

  - Microarchitectural Fill Buffer Data Sampling (MFBDS):
    Fill buffers on some microprocessors utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access. A list of impacted products
    can be found here:
    https://www.intel.com/content/dam/www/public/us/en/docu
    ments/corporate-information/SA00233-microcode-update-gu
    idance_05132019.pdf(CVE-2018-12130)

  - Microarchitectural Data Sampling Uncacheable Memory
    (MDSUM): Uncacheable memory on some microprocessors
    utilizing speculative execution may allow an
    authenticated user to potentially enable information
    disclosure via a side channel with local access. A list
    of impacted products can be found here:
    https://www.intel.com/content/dam/www/public/us/en/docu
    ments/corporate-information/SA00233-microcode-update-gu
    idance_05132019.pdf(CVE-2019-11091)

  - interface_release_resource in hw/display/qxl.c in QEMU
    4.0.0 has a NULL pointer dereference.(CVE-2019-12155)

  - Heap-based buffer overflow in the .receive callback of
    xlnx.xps-ethernetlite in QEMU (aka Quick Emulator)
    allows attackers to execute arbitrary code on the QEMU
    host via a large ethlite packet.(CVE-2016-7161)

  - Heap-based buffer overflow in the ne2000_receive
    function in hw/net/ne2000.c in QEMU before 2.4.0.1
    allows guest OS users to cause a denial of service
    (instance crash) or possibly execute arbitrary code via
    vectors related to receiving packets.(CVE-2015-5279)

  - The sdhci_sdma_transfer_multi_blocks function in
    hw/sd/sdhci.c in QEMU (aka Quick Emulator) allows local
    guest OS privileged users to cause a denial of service
    (out-of-bounds heap access and crash) or execute
    arbitrary code on the QEMU host via vectors involving
    the data transfer length.(CVE-2017-5667)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2227
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95b359a0");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu-kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-img-1.5.3-156.5.h14.eulerosv2r7",
        "qemu-kvm-1.5.3-156.5.h14.eulerosv2r7",
        "qemu-kvm-common-1.5.3-156.5.h14.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
