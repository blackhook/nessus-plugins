#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131805);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2012-2372",
    "CVE-2014-4157",
    "CVE-2014-4508",
    "CVE-2014-7843",
    "CVE-2014-8133",
    "CVE-2014-9870",
    "CVE-2014-9888",
    "CVE-2014-9892",
    "CVE-2015-3332",
    "CVE-2015-4001",
    "CVE-2015-4002",
    "CVE-2015-4003",
    "CVE-2015-4004",
    "CVE-2015-7833",
    "CVE-2015-8955",
    "CVE-2015-8967",
    "CVE-2015-9289",
    "CVE-2016-2186",
    "CVE-2016-3857",
    "CVE-2016-4486",
    "CVE-2016-6130",
    "CVE-2017-5897",
    "CVE-2017-7482",
    "CVE-2017-8831",
    "CVE-2017-13216",
    "CVE-2017-15537",
    "CVE-2017-16647",
    "CVE-2017-18551",
    "CVE-2018-7755",
    "CVE-2018-7995",
    "CVE-2018-9363",
    "CVE-2018-14625",
    "CVE-2018-20510",
    "CVE-2019-0136",
    "CVE-2019-3846",
    "CVE-2019-9506",
    "CVE-2019-10126",
    "CVE-2019-16231",
    "CVE-2019-16232",
    "CVE-2019-16234",
    "CVE-2019-16746",
    "CVE-2019-17075",
    "CVE-2019-17133",
    "CVE-2019-17666",
    "CVE-2019-18806",
    "CVE-2019-18808",
    "CVE-2019-19054",
    "CVE-2019-19060",
    "CVE-2019-19061",
    "CVE-2019-19062",
    "CVE-2019-19066"
  );
  script_bugtraq_id(
    54062,
    68083,
    68126,
    71082,
    71684,
    74232,
    74668,
    74672
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-2531)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2186)

  - The snd_compr_tstamp function in
    sound/core/compress_offload.c in the Linux kernel
    through 4.7, as used in Android before 2016-08-05 on
    Nexus 5 and 7 (2013) devices, does not properly
    initialize a timestamp data structure, which allows
    attackers to obtain sensitive information via a crafted
    application, aka Android internal bug 28770164 and
    Qualcomm internal bug CR568717.(CVE-2014-9892)

  - A memory leak in the cx23888_ir_probe() function in
    drivers/media/pci/cx23885/cx23888-ir.c in the Linux
    kernel through 5.3.11 allows attackers to cause a
    denial of service (memory consumption) by triggering
    kfifo_alloc() failures, aka
    CID-a7b2df76b42b.(CVE-2019-19054)

  - A memory leak in the adis_update_scan_mode() function
    in drivers/iio/imu/adis_buffer.c in the Linux kernel
    before 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-ab612b1daf41.(CVE-2019-19060)

  - A memory leak in the adis_update_scan_mode_burst()
    function in drivers/iio/imu/adis_buffer.c in the Linux
    kernel before 5.3.9 allows attackers to cause a denial
    of service (memory consumption), aka
    CID-9c0530e898f3.(CVE-2019-19061)

  - A memory leak in the crypto_report() function in
    crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service
    (memory consumption) by triggering crypto_report_alg()
    failures, aka CID-ffdde5932042.(CVE-2019-19062)

  - A memory leak in the ccp_run_sha_cmd() function in
    drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of
    service (memory consumption), aka
    CID-128c66429247.(CVE-2019-18808)

  - In ashmem_ioctl of ashmem.c, there is an out-of-bounds
    write due to insufficient locking when accessing asma.
    This could lead to a local elevation of privilege
    enabling code execution as a privileged process with no
    additional execution privileges needed. User
    interaction is not needed for exploitation. Product:
    Android. Versions: Android kernel. Android ID:
    A-66954097.(CVE-2017-13216)

  - A certain backport in the TCP Fast Open implementation
    for the Linux kernel before 3.18 does not properly
    maintain a count value, which allow local users to
    cause a denial of service (system crash) via the Fast
    Open feature, as demonstrated by visiting the
    chrome://flags/#enable-tcp-fast-open URL when using
    certain 3.10.x through 3.16.x kernel builds, including
    longterm-maintenance releases and ckt (aka Canonical
    Kernel Team) builds.(CVE-2015-3332)

  - The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel before 4.5.5
    does not initialize a certain data structure, which
    allows local users to obtain sensitive information from
    kernel stack memory by reading a Netlink
    message.(CVE-2016-4486)

  - The ip6gre_err function in net/ipv6/ip6_gre.c in the
    Linux kernel allows remote attackers to have
    unspecified impact via vectors involving GRE flags in
    an IPv6 packet, which trigger an out-of-bounds
    access.(CVE-2017-5897)

  - In the Linux kernel before version 4.12, Kerberos 5
    tickets decoded when using the RXRPC keys incorrectly
    assumes the size of a field. This could lead to the
    size-remaining variable wrapping and the data pointer
    going over the end of the buffer. This could possibly
    lead to memory corruption and possible privilege
    escalation.(CVE-2017-7482)

  - A flaw was found in the Linux Kernel where an attacker
    may be able to have an uncontrolled read to
    kernel-memory from within a vm guest. A race condition
    between connect() and close() function may allow an
    attacker using the AF_VSOCK protocol to gather a 4 byte
    information leak or possibly intercept or corrupt
    AF_VSOCK messages destined to other
    clients.(CVE-2018-14625)

  - drivers/net/usb/asix_devices.c in the Linux kernel
    through 4.13.11 allows local users to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact via a crafted
    USB device.(CVE-2017-16647)

  - A memory leak in the ql_alloc_large_buffers() function
    in drivers/net/ethernet/qlogic/qla3xxx.c in the Linux
    kernel before 5.3.5 allows local users to cause a
    denial of service (memory consumption) by triggering
    pci_dma_mapping_error() failures, aka
    CID-1acb8f2a7a9f.(CVE-2019-18806)

  - An issue was discovered in the fd_locked_ioctl function
    in drivers/block/floppy.c in the Linux kernel through
    4.15.7. The floppy driver will copy a kernel pointer to
    user memory in response to the FDGETPRM ioctl. An
    attacker can send the FDGETPRM ioctl and use the
    obtained kernel pointer to discover the location of
    kernel code and data and bypass kernel security
    protections such as KASLR.(CVE-2018-7755)

  - The usbvision driver in the Linux kernel package
    3.10.0-123.20.1.el7 through 3.10.0-229.14.1.el7 in Red
    Hat Enterprise Linux (RHEL) 7.1 allows physically
    proximate attackers to cause a denial of service
    (panic) via a nonzero bInterfaceNumber value in a USB
    device descriptor.(CVE-2015-7833)

  - A flaw that allowed an attacker to corrupt memory and
    possibly escalate privileges was found in the mwifiex
    kernel module while connecting to a malicious wireless
    network.(CVE-2019-3846)

  - drivers/net/wireless/marvell/libertas/if_sdio.c in the
    Linux kernel 5.2.14 does not check the alloc_workqueue
    return value, leading to a NULL pointer
    dereference.(CVE-2019-16232)

  - drivers/net/wireless/intel/iwlwifi/pcie/trans.c in the
    Linux kernel 5.2.14 does not check the alloc_workqueue
    return value, leading to a NULL pointer
    dereference.(CVE-2019-16234)

  - drivers/net/fjes/fjes_main.c in the Linux kernel 5.2.14
    does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference.(CVE-2019-16231)

  - Insufficient access control in the Intel(R)
    PROSet/Wireless WiFi Software driver before version
    21.10 may allow an unauthenticated user to potentially
    enable denial of service via adjacent
    access.(CVE-2019-0136)

  - A flaw was found in the Linux kernel. A heap based
    buffer overflow in mwifiex_uap_parse_tail_ies function
    in drivers/net/wireless/marvell/mwifiex/ie.c might lead
    to memory corruption and possibly other
    consequences.(CVE-2019-10126)

  - The Bluetooth BR/EDR specification up to and including
    version 5.1 permits sufficiently low encryption key
    length and does not prevent an attacker from
    influencing the key length negotiation. This allows
    practical brute-force attacks (aka 'KNOB') that can
    decrypt traffic and inject arbitrary ciphertext without
    the victim noticing.(CVE-2019-9506)

  - An issue was discovered in net/wireless/nl80211.c in
    the Linux kernel through 5.2.17. It does not check the
    length of variable elements in a beacon head, leading
    to a buffer overflow.(CVE-2019-16746)

  - In the hidp_process_report in bluetooth, there is an
    integer overflow. This could lead to an out of bounds
    write with no additional execution privileges needed.
    User interaction is not needed for exploitation.
    Product: Android Versions: Android kernel Android ID:
    A-65853588 References: Upstream kernel.(CVE-2018-9363)

  - An issue was discovered in write_tpt_entry in
    drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling
    dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of
    Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has
    security relevance.(CVE-2019-17075)

  - rtl_p2p_noa_ie in
    drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux
    kernel through 5.3.6 lacks a certain upper-bound check,
    leading to a buffer overflow.(CVE-2019-17666)

  - arch/arm/mm/dma-mapping.c in the Linux kernel before
    3.13 on ARM platforms, as used in Android before
    2016-08-05 on Nexus 5 and 7 (2013) devices, does not
    prevent executable DMA mappings, which might allow
    local users to gain privileges via a crafted
    application, aka Android internal bug 28803642 and
    Qualcomm internal bug CR642735.(CVE-2014-9888)

  - An issue was discovered in drivers/i2c/i2c-core-smbus.c
    in the Linux kernel before 4.14.15. There is an out of
    bounds write in the function
    i2c_smbus_xfer_emulated.(CVE-2017-18551)

  - The rds_ib_xmit function in net/rds/ib_send.c in the
    Reliable Datagram Sockets (RDS) protocol implementation
    in the Linux kernel 3.7.4 and earlier allows local
    users to cause a denial of service (BUG_ON and kernel
    panic) by establishing an RDS connection with the
    source IP address equal to the IPoIB interface's own IP
    address, as demonstrated by rds-ping.(CVE-2012-2372)

  - In the Linux kernel through 5.3.2,
    cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c
    does not reject a long SSID IE, leading to a Buffer
    Overflow.(CVE-2019-17133)

  - A memory leak in the bfad_im_get_stats() function in
    drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of
    service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka
    CID-0e62395da2bd.(CVE-2019-19066)

  - The kernel in Android before 2016-08-05 on Nexus 7
    (2013) devices allows attackers to gain privileges via
    a crafted application, aka internal bug
    28522518.(CVE-2016-3857)

  - arch/arm64/kernel/sys.c in the Linux kernel before 4.0
    allows local users to bypass the 'strict page
    permissions' protection mechanism and modify the
    system-call table, and consequently gain privileges, by
    leveraging write access.(CVE-2015-8967)

  - arch/arm64/kernel/perf_event.c in the Linux kernel
    before 4.1 on arm64 platforms allows local users to
    gain privileges or cause a denial of service (invalid
    pointer dereference) via vectors involving events that
    are mishandled during a span of multiple HW
    PMUs.(CVE-2015-8955)

  - The __clear_user function in
    arch/arm64/lib/clear_user.S in the Linux kernel before
    3.17.4 on the ARM64 platform allows local users to
    cause a denial of service (system crash) by reading one
    byte beyond a /dev/zero page boundary.(CVE-2014-7843)

  - The x86/fpu (Floating Point Unit) subsystem in the
    Linux kernel before 4.13.5, when a processor supports
    the xsave feature but not the xsaves feature, does not
    correctly handle attempts to set reserved bits in the
    xstate header via the ptrace() or rt_sigreturn() system
    call, allowing local users to read the FPU registers of
    other processes on the system, related to
    arch/x86/kernel/fpu/regset.c and
    arch/x86/kernel/fpu/signal.c.(CVE-2017-15537)

  - The Linux kernel before 3.11 on ARM platforms, as used
    in Android before 2016-08-05 on Nexus 5 and 7 (2013)
    devices, does not properly consider user-space access
    to the TPIDRURW register, which allows local users to
    gain privileges via a crafted application, aka Android
    internal bug 28749743 and Qualcomm internal bug
    CR561044.(CVE-2014-9870)

  - ** DISPUTED ** Race condition in the
    store_int_with_restart() function in
    arch/x86/kernel/cpu/mcheck/mce.c in the Linux kernel
    through 4.15.7 allows local users to cause a denial of
    service (panic) by leveraging root access to write to
    the check_interval file in a
    /sys/devices/system/machinecheck/machinecheck
    directory. NOTE: a third party has indicated that this
    report is not security relevant.(CVE-2018-7995)

  - arch/x86/kernel/entry_32.S in the Linux kernel through
    3.15.1 on 32-bit x86 platforms, when syscall auditing
    is enabled and the sep CPU feature flag is set, allows
    local users to cause a denial of service (OOPS and
    system crash) via an invalid syscall number, as
    demonstrated by number 1000.(CVE-2014-4508)

  - arch/x86/kernel/tls.c in the Thread Local Storage (TLS)
    implementation in the Linux kernel through 3.18.1
    allows local users to bypass the espfix protection
    mechanism, and consequently makes it easier for local
    users to bypass the ASLR protection mechanism, via a
    crafted application that makes a set_thread_area system
    call and later reads a 16-bit value.(CVE-2014-8133)

  - arch/mips/include/asm/thread_info.h in the Linux kernel
    before 3.14.8 on the MIPS platform does not configure
    _TIF_SECCOMP checks on the fast system-call path, which
    allows local users to bypass intended PR_SET_SECCOMP
    restrictions by executing a crafted application without
    invoking a trace or audit subsystem.(CVE-2014-4157)

  - Integer signedness error in the oz_hcd_get_desc_cnf
    function in drivers/staging/ozwpan/ozhcd.c in the
    OZWPAN driver in the Linux kernel through 4.0.5 allows
    remote attackers to cause a denial of service (system
    crash) or possibly execute arbitrary code via a crafted
    packet.(CVE-2015-4001)

  - drivers/staging/ozwpan/ozusbsvc1.c in the OZWPAN driver
    in the Linux kernel through 4.0.5 does not ensure that
    certain length values are sufficiently large, which
    allows remote attackers to cause a denial of service
    (system crash or large loop) or possibly execute
    arbitrary code via a crafted packet, related to the (1)
    oz_usb_rx and (2) oz_usb_handle_ep_data
    functions.(CVE-2015-4002)

  - The oz_usb_handle_ep_data function in
    drivers/staging/ozwpan/ozusbsvc1.c in the OZWPAN driver
    in the Linux kernel through 4.0.5 allows remote
    attackers to cause a denial of service (divide-by-zero
    error and system crash) via a crafted
    packet.(CVE-2015-4003)

  - The OZWPAN driver in the Linux kernel through 4.0.5
    relies on an untrusted length field during packet
    parsing, which allows remote attackers to obtain
    sensitive information from kernel memory or cause a
    denial of service (out-of-bounds read and system crash)
    via a crafted packet.(CVE-2015-4004)

  - Race condition in the sclp_ctl_ioctl_sccb function in
    drivers/s390/char/sclp_ctl.c in the Linux kernel before
    4.6 allows local users to obtain sensitive information
    from kernel memory by changing a certain length value,
    aka a 'double fetch' vulnerability.(CVE-2016-6130)

  - The print_binder_transaction_ilocked function in
    drivers/android/binder.c in the Linux kernel 4.14.90
    allows local users to obtain sensitive address
    information by reading '*from *code *flags' lines in a
    debugfs file.(CVE-2018-20510)

  - In the Linux kernel before 4.1.4, a buffer overflow
    occurs when checking userspace params in
    drivers/media/dvb-frontends/cx24116.c. The maximum size
    for a DiSEqC command is 6, according to the userspace
    API. However, the code allows larger values such as
    23.(CVE-2015-9289)

  - The saa7164_bus_get function in
    drivers/media/pci/saa7164/saa7164-bus.c in the Linux
    kernel through 4.11.5 allows local users to cause a
    denial of service (out-of-bounds array access) or
    possibly have unspecified other impact by changing a
    certain sequence-number value, aka a 'double fetch'
    vulnerability.(CVE-2017-8831)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2531
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2de1205c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3857");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
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

pkgs = ["kernel-3.10.0-862.14.1.5.h328.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h328.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h328.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h328.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h328.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h328.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h328.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
