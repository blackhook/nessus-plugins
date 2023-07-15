#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139137);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-18282",
    "CVE-2019-20806",
    "CVE-2019-20810",
    "CVE-2019-20811",
    "CVE-2019-20812",
    "CVE-2019-9445",
    "CVE-2020-0009",
    "CVE-2020-0543",
    "CVE-2020-10135",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10757",
    "CVE-2020-10766",
    "CVE-2020-10767",
    "CVE-2020-10768",
    "CVE-2020-10781",
    "CVE-2020-12888",
    "CVE-2020-13143",
    "CVE-2020-13974",
    "CVE-2020-14416",
    "CVE-2020-15393"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-1807)");
  script_summary(english:"Checks the rpm output for the updated packages.");

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
    output, etc.Security Fix(es):An issue was discovered in
    the Linux kernel before 5.2. There is a NULL pointer
    dereference in tw5864_handle_frame() in
    drivers/media/pci/tw5864/tw5864-video.c, which may
    cause denial of service, aka
    CID-2e7682ebfc75.(CVE-2019-20806)A flaw was found in
    the ZRAM kernel module, where a user with a local
    account and the ability to read the
    /sys/class/zram-control/hot_add file can create ZRAM
    device nodes in the /dev/ directory. This read
    allocates kernel memory and is not accounted for a user
    that triggers the creation of that ZRAM device. With
    this vulnerability, continually reading the device may
    consume a large amount of system memory and cause the
    Out-of-Memory (OOM) killer to activate and terminate
    random userspace processes, possibly making the system
    inoperable.(CVE-2020-10781)In the Linux kernel before
    5.4.16, a race condition in tty->disc_data handling in
    the slip and slcan line discipline could lead to a
    use-after-free, aka CID-0ace17d56824. This affects
    drivers/ net/slip/slip.c and drivers/
    net/can/slcan.c.(CVE-2020-14416)The VFIO PCI driver in
    the Linux kernel through 5.6.13 mishandles attempts to
    access disabled memory space.(CVE-2020-12888)The
    flow_dissector feature in the Linux kernel 4.3 through
    5.x before 5.3.10 has a device tracking vulnerability,
    aka CID-55667441c84f. This occurs because the auto
    flowlabel of a UDP IPv6 packet relies on a 32-bit
    hashrnd value as a secret, and because jhash (instead
    of siphash) is used. The hashrnd value remains the same
    starting from boot time, and can be inferred by an
    attacker. This affects net/core/flow_dissector.c and
    related code.(CVE-2019-18282)In the Linux kernel
    through 5.7.6, usbtest_disconnect in
    drivers/usb/misc/usbtest.c has a memory leak, aka
    CID-28ebeb8db770.(CVE-2020-15393)An issue was
    discovered in the Linux kernel before 5.0.6. In
    rx_queue_add_kobject() and netdev_queue_add_kobject()
    in net/core/ net-sysfs.c, a reference count is
    mishandled, aka CID-a3e23f719f5c.(CVE-2019-20811)A flaw
    was found in the Linux kernels SELinux LSM hook
    implementation before version 5.7, where it incorrectly
    assumed that an skb would only contain a single netlink
    message. The hook would incorrectly only validate the
    first netlink message in the skb and allow or deny the
    rest of the messages within the skb with the granted
    permission without further
    processing.(CVE-2020-10751)In the Android kernel in
    F2FS driver there is a possible out of bounds read due
    to a missing bounds check. This could lead to local
    information disclosure with system execution privileges
    needed. User interaction is not needed for
    exploitation.(CVE-2019-9445)A flaw was found in the
    Linux kernel's implementation of Userspace core dumps.
    This flaw allows an attacker with a local account to
    crash a trivial program and exfiltrate private kernel
    data.(CVE-2020-10732)go7007_snd_init in
    drivers/media/usb/go7007/snd-go7007.c in the Linux
    kernel before 5.6 does not call snd_card_free for a
    failure path, which causes a memory leak, aka
    CID-9453264ef586.(CVE-2019-20810)Legacy pairing and
    secure-connections pairing authentication in Bluetooth(r)
    BR/EDR Core Specification v5.2 and earlier may allow an
    unauthenticated user to complete authentication without
    pairing credentials via adjacent access. An
    unauthenticated, adjacent attacker could impersonate a
    Bluetooth BR/EDR master or slave to pair with a
    previously paired remote device to successfully
    complete the authentication procedure without knowing
    the link key.(CVE-2020-10135)An issue was discovered in
    the Linux kernel before 5.4.7. The
    prb_calc_retire_blk_tmo() function in
    net/packet/af_packet.c can result in a denial of
    service (CPU consumption and soft lockup) in a certain
    failure case involving TPACKET_V3, aka
    CID-b43d1f9f7067.(CVE-2019-20812)An issue was
    discovered in the Linux kernel through 5.7.1.
    drivers/tty/vt/keyboard.c has an integer overflow if
    k_ascii is called several times in a row, aka
    CID-b86dab054059. NOTE: Members in the community argue
    that the integer overflow does not lead to a security
    issue in this case.(CVE-2020-13974)In calc_vm_may_flags
    of ashmem.c, there is a possible arbitrary write to
    shared memory due to a permissions bypass. This could
    lead to local escalation of privilege by corrupting
    memory shared between processes, with no additional
    execution privileges needed. User interaction is not
    needed for exploitation. Product: Android Versions:
    Android kernel Android ID: A-142938932(CVE-2020-0009)A
    flaw was found in the Linux Kernel in versions after
    4.5-rc1 in the way mremap handled DAX Huge Pages. This
    flaw allows a local attacker with access to a DAX
    enabled storage to escalate their privileges on the
    system.(CVE-2020-10757)gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c in the Linux kernel
    through 5.6.13 relies on kstrdup without considering
    the possibility of an internal '\0' value, which allows
    attackers to trigger an out-of-bounds read, aka
    CID-15753588bcd4.(CVE-2020-13143)Incomplete cleanup
    from specific special register read operations in some
    Intel(R) Processors may allow an authenticated user to
    potentially enable information disclosure via local
    access.(CVE-2020-0543)A flaw was found in the prctl()
    function, where it can be used to enable indirect
    branch speculation after it has been disabled. This
    call incorrectly reports it as being 'force disabled'
    when it is not and opens the system to Spectre v2
    attacks. The highest threat from this vulnerability is
    to confidentiality.(CVE-2020-10768)A flaw was found in
    the Linux kernel's implementation of the Enhanced IBPB
    (Indirect Branch Prediction Barrier). The IBPB
    mitigation will be disabled when STIBP is not available
    or when the Enhanced Indirect Branch Restricted
    Speculation (IBRS) is available. This flaw allows a
    local attacker to perform a Spectre V2 style attack
    when this configuration is active. The highest threat
    from this vulnerability is to
    confidentiality.(CVE-2020-10767)A logic bug flaw was
    found in the Linux kernel's implementation of SSBD. A
    bug in the logic handling allows an attacker with a
    local account to disable SSBD protection during a
    context switch when additional speculative execution
    mitigations are in place. This issue was introduced
    when the per task/process conditional STIPB switching
    was added on top of the existing SSBD switching. The
    highest threat from this vulnerability is to
    confidentiality.(CVE-2020-10766)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1807
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e94ba4c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h794.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h794.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
