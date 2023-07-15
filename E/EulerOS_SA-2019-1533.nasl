#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124986);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2013-4515",
    "CVE-2013-6378",
    "CVE-2014-0196",
    "CVE-2014-3673",
    "CVE-2014-3690",
    "CVE-2014-9715",
    "CVE-2014-9731",
    "CVE-2015-2672",
    "CVE-2015-6937",
    "CVE-2015-7613",
    "CVE-2015-8844",
    "CVE-2016-0821",
    "CVE-2016-2066",
    "CVE-2016-6156",
    "CVE-2017-1000251",
    "CVE-2017-18200",
    "CVE-2017-2671",
    "CVE-2018-10883",
    "CVE-2018-15594",
    "CVE-2018-5344"
  );
  script_bugtraq_id(
    63518,
    63886,
    67199,
    67282,
    70691,
    70883,
    73953,
    75001
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1533)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An integer overflow flaw was found in the way the Linux
    kernel's netfilter connection tracking implementation
    loaded extensions. An attacker on a local network could
    potentially send a sequence of specially crafted
    packets that would initiate the loading of a large
    number of extensions, causing the targeted system in
    that network to crash.(CVE-2014-9715i1/4%0

  - A flaw was found in the Linux kernel which could cause
    a kernel panic when restoring machine specific
    registers on the PowerPC platform. Incorrect
    transactional memory state registers could
    inadvertently change the call path on return from
    userspace and cause the kernel to enter an unknown
    state and crash.(CVE-2015-8844i1/4%0

  - A timing flaw was found in the Chrome EC driver in the
    Linux kernel. An attacker could abuse timing to skip
    validation checks to copy additional data from
    userspace possibly increasing privilege or crashing the
    system.(CVE-2016-6156i1/4%0

  - A race condition flaw was found in the way the Linux
    kernel's IPC subsystem initialized certain fields in an
    IPC object structure that were later used for
    permission checking before inserting the object into a
    globally visible list. A local, unprivileged user could
    potentially use this flaw to elevate their privileges
    on the system.(CVE-2015-7613i1/4%0

  - A path length checking flaw was found in Linux kernels
    built with UDF file system (CONFIG_UDF_FS) support. An
    attacker able to mount a corrupted/malicious UDF file
    system image could use this flaw to leak kernel memory
    to user-space.(CVE-2014-9731i1/4%0

  - A race condition leading to a NULL pointer dereference
    was found in the Linux kernel's Link Layer Control
    implementation. A local attacker with access to ping
    sockets could use this flaw to crash the
    system.(CVE-2017-2671i1/4%0

  - The f2fs implementation in the Linux kernel, before
    4.14, mishandles reference counts associated with
    f2fs_wait_discard_bios calls. This allows local users
    to cause a denial of service (BUG), as demonstrated by
    fstrim.(CVE-2017-18200i1/4%0

  - The LIST_POISON feature in include/linux/poison.h in
    the Linux kernel before 4.3, as used in Android 6.0.1
    before 2016-03-01, does not properly consider the
    relationship to the mmap_min_addr value, which makes it
    easier for attackers to bypass a poison-pointer
    protection mechanism by triggering the use of an
    uninitialized list entry, aka Android internal bug
    26186802, a different vulnerability than
    CVE-2015-3636.(CVE-2016-0821i1/4%0

  - The xsave/xrstor implementation in
    arch/x86/include/asm/xsave.h in the Linux kernel before
    3.19.2 creates certain .altinstr_replacement pointers
    and consequently does not provide any protection
    against instruction faulting, which allows local users
    to cause a denial of service (panic) by triggering a
    fault, as demonstrated by an unaligned memory operand
    or a non-canonical address memory
    operand.(CVE-2015-2672i1/4%0

  - The n_tty_write function in drivers/tty/n_tty.c in the
    Linux kernel through 3.14.3 does not properly manage
    tty driver access in the 'LECHO i1/4+ !OPOST' case, which
    allows local users to cause a denial of service (memory
    corruption and system crash) or gain privileges by
    triggering a race condition involving read and write
    operations with long strings.(CVE-2014-0196i1/4%0

  - In the Linux kernel through 4.14.13,
    drivers/block/loop.c mishandles lo_release
    serialization, which allows attackers to cause a denial
    of service (__lock_acquire use-after-free) or possibly
    have unspecified other impact.(CVE-2018-5344i1/4%0

  - The lbs_debugfs_write function in
    drivers/net/wireless/libertas/debugfs.c in the Linux
    kernel through 3.12.1 allows local users to cause a
    denial of service (OOPS) by leveraging root privileges
    for a zero-length write operation.(CVE-2013-6378i1/4%0

  - A NULL-pointer dereference vulnerability was discovered
    in the Linux kernel. The kernel's Reliable Datagram
    Sockets (RDS) protocol implementation did not verify
    that an underlying transport existed before creating a
    connection to a remote server. A local system user
    could exploit this flaw to crash the system by creating
    sockets at specific times to trigger a NULL pointer
    dereference.(CVE-2015-6937i1/4%0

  - A stack buffer overflow flaw was found in the way the
    Bluetooth subsystem of the Linux kernel processed
    pending L2CAP configuration responses from a client. On
    systems with the stack protection feature enabled in
    the kernel (CONFIG_CC_STACKPROTECTOR=y, which is
    enabled on all architectures other than s390x and
    ppc64le), an unauthenticated attacker able to initiate
    a connection to a system via Bluetooth could use this
    flaw to crash the system. Due to the nature of the
    stack protection feature, code execution cannot be
    fully ruled out, although we believe it is unlikely. On
    systems without the stack protection feature (ppc64le
    the Bluetooth modules are not built on s390x), an
    unauthenticated attacker able to initiate a connection
    to a system via Bluetooth could use this flaw to
    remotely execute arbitrary code on the system with ring
    0 (kernel) privileges.(CVE-2017-1000251i1/4%0

  - Integer signedness error in the MSM QDSP6 audio driver
    for the Linux kernel 3.x, as used in Qualcomm
    Innovation Center (QuIC) Android contributions for MSM
    devices and other products, allows attackers to gain
    privileges or cause a denial of service (memory
    corruption) via a crafted application that makes an
    ioctl call.(CVE-2016-2066i1/4%0

  - The bcm_char_ioctl function in
    drivers/staging/bcm/Bcmchar.c in the Linux kernel
    before 3.12 does not initialize a certain data
    structure, which allows local users to obtain sensitive
    information from kernel memory via an
    IOCTL_BCM_GET_DEVICE_DRIVER_INFO ioctl
    call.(CVE-2013-4515i1/4%0

  - A flaw was found in the way the Linux kernel's Stream
    Control Transmission Protocol (SCTP) implementation
    handled malformed Address Configuration Change Chunks
    (ASCONF). A remote attacker could use either of these
    flaws to crash the system.(CVE-2014-3673i1/4%0

  - It was found that paravirt_patch_call/jump() functions
    in the arch/x86/kernel/paravirt.c in the Linux kernel
    mishandles certain indirect calls, which makes it
    easier for attackers to conduct Spectre-v2 attacks
    against paravirtualized guests.(CVE-2018-15594i1/4%0

  - It was found that the Linux kernel's KVM implementation
    did not ensure that the host CR4 control register value
    remained unchanged across VM entries on the same
    virtual CPU. A local, unprivileged user could use this
    flaw to cause a denial of service on the
    system.(CVE-2014-3690i1/4%0

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound write in
    jbd2_journal_dirty_metadata(), a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image.(CVE-2018-10883i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1533
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6ad58ff");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000251");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
