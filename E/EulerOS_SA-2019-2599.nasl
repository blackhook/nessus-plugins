#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132134);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2014-4608",
    "CVE-2014-5206",
    "CVE-2014-5207",
    "CVE-2015-1350",
    "CVE-2015-3332",
    "CVE-2015-8816",
    "CVE-2015-8844",
    "CVE-2015-8845",
    "CVE-2015-9289",
    "CVE-2016-2184",
    "CVE-2016-2185",
    "CVE-2016-2186",
    "CVE-2016-2187",
    "CVE-2016-2384",
    "CVE-2016-3138",
    "CVE-2016-3139",
    "CVE-2016-3140",
    "CVE-2016-3689",
    "CVE-2016-4569",
    "CVE-2016-4578",
    "CVE-2016-6130",
    "CVE-2016-6197",
    "CVE-2016-7425",
    "CVE-2017-5753",
    "CVE-2017-13168",
    "CVE-2017-18509",
    "CVE-2017-18551",
    "CVE-2017-18595",
    "CVE-2017-1000253",
    "CVE-2017-1000379",
    "CVE-2018-14617",
    "CVE-2019-0136",
    "CVE-2019-17075",
    "CVE-2019-17133",
    "CVE-2019-17666"
  );
  script_bugtraq_id(
    68214,
    69214,
    69216,
    74232
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2019-2599)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):** DISPUTED ** Multiple
    integer overflows in the lzo1x_decompress_safe function
    in lib/lzo/lzo1x_decompress_safe.c in the LZO
    decompressor in the Linux kernel before 3.15.2 allow
    context-dependent attackers to cause a denial of
    service (memory corruption) via a crafted Literal Run.
    NOTE: the author of the LZO algorithms says 'the Linux
    kernel is *not* affected media hype.'(CVE-2014-4608)A
    certain backport in the TCP Fast Open implementation
    for the Linux kernel before 3.18 does not properly
    maintain a count value, which allow local users to
    cause a denial of service (system crash) via the Fast
    Open feature, as demonstrated by visiting the
    chrome://flags/#enable-tcp-fast-open URL when using
    certain 3.10.x through 3.16.x kernel builds, including
    longterm-maintenance releases and ckt (aka Canonical
    Kernel Team) builds.(CVE-2015-3332)An elevation of
    privilege vulnerability in the kernel scsi driver.
    Product: Android. Versions: Android kernel. Android ID
    A-65023233.(CVE-2017-13168)An issue was discovered in
    drivers/i2c/i2c-core-smbus.c in the Linux kernel before
    4.14.15. There is an out of bounds write in the
    function i2c_smbus_xfer_emulated.(CVE-2017-18551)An
    issue was discovered in net/ipv6/ip6mr.c in the Linux
    kernel before 4.11. By setting a specific socket
    option, an attacker can control a pointer in kernel
    land and cause an inet_csk_listen_stop general
    protection fault, or potentially execute arbitrary code
    under certain circumstances. The issue can be triggered
    as root (e.g., inside a default LXC container or with
    the CAP_NET_ADMIN capability) or after namespace
    unsharing. This occurs because sk_type and protocol are
    not checked in the appropriate part of the ip6_mroute_*
    functions. NOTE: this affects Linux distributions that
    use 4.9.x longterm kernels before
    4.9.187.(CVE-2017-18509)An issue was discovered in the
    Linux kernel before 4.14.11. A double free may be
    caused by the function allocate_trace_buffer in the
    file kernel/trace/trace.c.(CVE-2017-18595)An issue was
    discovered in the Linux kernel through 4.17.10. There
    is a NULL pointer dereference and panic in
    hfsplus_lookup() in fs/hfsplus/dir.c when opening a
    file (that is purportedly a hard link) in an hfs+
    filesystem that has malformed catalog data, and is
    mounted read-only without a metadata
    directory.(CVE-2018-14617)An issue was discovered in
    write_tpt_entry in drivers/infiniband/hw/cxgb4/mem.c in
    the Linux kernel through 5.3.2. The cxgb4 driver is
    directly calling dma_map_single (a DMA function) from a
    stack variable. This could allow an attacker to trigger
    a Denial of Service, exploitable if this driver is used
    on an architecture for which this stack/DMA interaction
    has security relevance.(CVE-2019-17075)Double free
    vulnerability in the snd_usbmidi_create function in
    sound/usb/midi.c in the Linux kernel before 4.5 allows
    physically proximate attackers to cause a denial of
    service (panic) or possibly have unspecified other
    impact via vectors involving an invalid USB
    descriptor.(CVE-2016-2384)fsamespace.c in the Linux
    kernel through 3.16.1 does not properly restrict
    clearing MNT_NODEV, MNT_NOSUID, and MNT_NOEXEC and
    changing MNT_ATIME_MASK during a remount of a bind
    mount, which allows local users to gain privileges,
    interfere with backups and auditing on systems that had
    atime enabled, or cause a denial of service (excessive
    filesystem updating) on systems that had atime disabled
    via a 'mount -o remount' command within a user
    namespace.(CVE-2014-5207)fs/overlayfs/dir.c in the
    OverlayFS filesystem implementation in the Linux kernel
    before 4.6 does not properly verify the upper dentry
    before proceeding with unlink and rename system-call
    processing, which allows local users to cause a denial
    of service (system crash) via a rename system call that
    specifies a self-hardlink.(CVE-2016-6197)In the Linux
    kernel before 4.1.4, a buffer overflow occurs when
    checking userspace params in
    drivers/media/dvb-frontends/cx24116.c. The maximum size
    for a DiSEqC command is 6, according to the userspace
    API. However, the code allows larger values such as
    23.(CVE-2015-9289)In the Linux kernel through 5.3.2,
    cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c
    does not reject a long SSID IE, leading to a Buffer
    Overflow.(CVE-2019-17133)Insufficient access control in
    the Intel(R) PROSet/Wireless WiFi Software driver
    before version 21.10 may allow an unauthenticated user
    to potentially enable denial of service via adjacent
    access.(CVE-2019-0136)Linux distributions that have not
    patched their long-term kernels with
    https://git.kernel.org/linus/a87938b2e246b81b4fb713edb3
    71a9fa3c5c3c86 (committed on April 14, 2015). This
    kernel vulnerability was fixed in April 2015 by commit
    a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (backported to
    Linux 3.10.77 in May 2015), but it was not recognized
    as a security threat. With
    CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE enabled, and a
    normal top-down address allocation strategy,
    load_elf_binary() will attempt to map a PIE binary into
    an address range immediately below mm->mmap_base.
    Unfortunately, load_elf_ binary() does not take account
    of the need to allocate sufficient space for the entire
    binary which means that, while the first PT_LOAD
    segment is mapped below mm->mmap_base, the subsequent
    PT_LOAD segment(s) end up being mapped above
    mm->mmap_base into the are that is supposed to be the
    'gap' between the stack and the
    binary.(CVE-2017-1000253)Race condition in the
    sclp_ctl_ioctl_sccb function in
    drivers/s390/char/sclp_ctl.c in the Linux kernel before
    4.6 allows local users to obtain sensitive information
    from kernel memory by changing a certain length value,
    aka a 'double fetch'
    vulnerability.(CVE-2016-6130)rtl_p2p_noa_ie in drivers
    et/wireless/realtek/rtlwifi/ps.c in the Linux kernel
    through 5.3.6 lacks a certain upper-bound check,
    leading to a buffer
    overflow.(CVE-2019-17666)sound/core/timer.c in the
    Linux kernel through 4.6 does not initialize certain r1
    data structures, which allows local users to obtain
    sensitive information from kernel stack memory via
    crafted use of the ALSA timer interface, related to the
    (1) snd_timer_user_ccallback and (2)
    snd_timer_user_tinterrupt
    functions.(CVE-2016-4578)Systems with microprocessors
    utilizing speculative execution and branch prediction
    may allow unauthorized disclosure of information to an
    attacker with local user access via a side-channel
    analysis.(CVE-2017-5753)The acm_probe function in
    drivers/usb/class/cdc-acm.c in the Linux kernel before
    4.5.1 allows physically proximate attackers to cause a
    denial of service (NULL pointer dereference and system
    crash) via a USB device without both a control and a
    data endpoint descriptor.(CVE-2016-3138)The
    arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel
    through 4.8.2 does not restrict a certain length field,
    which allows local users to gain privileges or cause a
    denial of service (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control
    code.(CVE-2016-7425)The ati_remote2_probe function in
    drivers/input/misc/ati_remote2.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2185)The
    create_fixed_stream_quirk function in
    sound/usb/quirks.c in the snd-usb-audio driver in the
    Linux kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference or double free, and system crash) via a
    crafted endpoints value in a USB device
    descriptor.(CVE-2016-2184)The digi_port_init function
    in drivers/usb/serial/digi_acceleport.c in the Linux
    kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) via a crafted endpoints
    value in a USB device descriptor.(CVE-2016-3140)The
    do_remount function in fsamespace.c in the Linux kernel
    through 3.16.1 does not maintain the MNT_LOCK_READONLY
    bit across a remount of a bind mount, which allows
    local users to bypass an intended read-only restriction
    and defeat certain sandbox protection mechanisms via a
    'mount -o remount' command within a user
    namespace.(CVE-2014-5206)The gtco_probe function in
    drivers/input/tablet/gtco.c in the Linux kernel through
    4.5.2 allows physically proximate attackers to cause a
    denial of service (NULL pointer dereference and system
    crash) via a crafted endpoints value in a USB device
    descriptor.(CVE-2016-2187)The hub_activate function in
    drivers/usb/core/hub.c in the Linux kernel before 4.3.5
    does not properly maintain a hub-interface data
    structure, which allows physically proximate attackers
    to cause a denial of service (invalid memory access and
    system crash) or possibly have unspecified other impact
    by unplugging a USB hub device.(CVE-2015-8816)The
    ims_pcu_parse_cdc_data function in
    drivers/input/misc/ims-pcu.c in the Linux kernel before
    4.5.1 allows physically proximate attackers to cause a
    denial of service (system crash) via a USB device
    without both a master and a slave
    interface.(CVE-2016-3689)The Linux Kernel running on
    AMD64 systems will sometimes map the contents of PIE
    executable, the heap or ld.so to where the stack is
    mapped allowing attackers to more easily manipulate the
    stack. Linux Kernel version 4.11.5 is
    affected.(CVE-2017-1000379)The powermate_probe function
    in drivers/input/misc/powermate.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2186)The signal
    implementation in the Linux kernel before 4.3.5 on
    powerpc platforms does not check for an MSR with both
    the S and T bits set, which allows local users to cause
    a denial of service (TM Bad Thing exception and panic)
    via a crafted application.(CVE-2015-8844)The
    snd_timer_user_params function in sound/core/timer.c in
    the Linux kernel through 4.6 does not initialize a
    certain data structure, which allows local users to
    obtain sensitive information from kernel stack memory
    via crafted use of the ALSA timer
    interface.(CVE-2016-4569)The tm_reclaim_thread function
    in arch/powerpc/kernel/process.c in the Linux kernel
    before 4.4.1 on powerpc platforms does not ensure that
    TM suspend mode exists before proceeding with a
    tm_reclaim call, which allows local users to cause a
    denial of service (TM Bad Thing exception and panic)
    via a crafted application.(CVE-2015-8845)The VFS
    subsystem in the Linux kernel 3.x provides an
    incomplete set of requirements for setattr operations
    that underspecifies removing extended privilege
    attributes, which allows local users to cause a denial
    of service (capability stripping) via a failed
    invocation of a system call, as demonstrated by using
    chown to remove a capability from the ping or Wireshark
    dumpcap program.(CVE-2015-1350)The wacom_probe function
    in drivers/input/tablet/wacom_sys.c in the Linux kernel
    before 3.17 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-3139)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2599
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc6af25f");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h234",
        "kernel-debuginfo-3.10.0-514.44.5.10.h234",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h234",
        "kernel-devel-3.10.0-514.44.5.10.h234",
        "kernel-headers-3.10.0-514.44.5.10.h234",
        "kernel-tools-3.10.0-514.44.5.10.h234",
        "kernel-tools-libs-3.10.0-514.44.5.10.h234",
        "perf-3.10.0-514.44.5.10.h234",
        "python-perf-3.10.0-514.44.5.10.h234"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
