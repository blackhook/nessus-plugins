#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124977);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-7026",
    "CVE-2014-4699",
    "CVE-2014-6416",
    "CVE-2014-7970",
    "CVE-2014-9584",
    "CVE-2014-9892",
    "CVE-2014-9922",
    "CVE-2015-0275",
    "CVE-2015-2925",
    "CVE-2016-2548",
    "CVE-2016-2782",
    "CVE-2016-9756",
    "CVE-2017-6346",
    "CVE-2017-7889",
    "CVE-2017-11472",
    "CVE-2017-17975",
    "CVE-2018-5953",
    "CVE-2018-5995",
    "CVE-2018-14617",
    "CVE-2018-18559"
  );
  script_bugtraq_id(
    64312,
    68411,
    69805,
    70319,
    71883,
    73926,
    75139
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1524)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - In the Linux kernel through 4.19, a use-after-free can
    occur due to a race condition between fanout_add from
    setsockopt and bind on an AF_PACKET socket. This issue
    exists because of the
    15fe076edea787807a7cdc168df832544b58eba6 incomplete fix
    for a race condition. The code mishandles a certain
    multithreaded case involving a packet_do_bind
    unregister action followed by a packet_notifier
    register action. Later, packet_release operates on only
    one of the two applicable linked lists. The attacker
    can achieve Program Counter control.(CVE-2018-18559i1/4%0

  - The acpi_ns_terminate() function in
    drivers/acpi/acpica/nsutils.c in the Linux kernel
    before 4.12 does not flush the operand cache and causes
    a kernel stack dump. A local users could obtain
    sensitive information from kernel memory and bypass the
    KASLR protection mechanism (in the kernel through 4.9)
    via a crafted ACPI table.(CVE-2017-11472i1/4%0

  - Race condition in net/packet/af_packet.c in the Linux
    kernel allows local users to cause a denial of service
    (use-after-free) or possibly have unspecified other
    impact via a multithreaded application that makes
    PACKET_FANOUT setsockopt system calls.(CVE-2017-6346i1/4%0

  - Multiple race conditions in ipc/shm.c in the Linux
    kernel before 3.12.2 allow local users to cause a
    denial of service (use-after-free and system crash) or
    possibly have unspecified other impact via a crafted
    application that uses shmctl IPC_RMID operations in
    conjunction with other shm system
    calls.(CVE-2013-7026i1/4%0

  - An issue was discovered in the Linux kernel. A NULL
    pointer dereference and panic in hfsplus_lookup() in
    the fs/hfsplus/dir.c function can occur when opening a
    file (that is purportedly a hard link) in an hfs+
    filesystem that has malformed catalog data, and is
    mounted read-only without a metadata
    directory.(CVE-2018-14617i1/4%0

  - The treo_attach function in drivers/usb/serial/visor.c
    in the Linux kernel before 4.5 allows physically
    proximate attackers to cause a denial of service (NULL
    pointer dereference and system crash) or possibly have
    unspecified other impact by inserting a USB device that
    lacks a (1) bulk-in or (2) interrupt-in
    endpoint.(CVE-2016-2782i1/4%0

  - An information-exposure flaw was found in the Linux
    kernel where the pcpu_embed_first_chunk() function in
    mm/percpu.c allows local users to obtain kernel-object
    address information by reading the kernel log (dmesg).
    However, this address is not static and cannot be used
    to commit a further attack.(CVE-2018-5995i1/4%0

  - Buffer overflow in net/ceph/auth_x.c in Ceph, as used
    in the Linux kernel before 3.16.3, allows remote
    attackers to cause a denial of service (memory
    corruption and panic) or possibly have unspecified
    other impact via a long unencrypted auth
    ticket.(CVE-2014-6416i1/4%0

  - It was found that the Linux kernel's ptrace subsystem
    allowed a traced process' instruction pointer to be set
    to a non-canonical memory address without forcing the
    non-sysret code path when returning to user space. A
    local, unprivileged user could use this flaw to crash
    the system or, potentially, escalate their privileges
    on the system.Note: The CVE-2014-4699 issue only
    affected systems using an Intel CPU.(CVE-2014-4699i1/4%0

  - The snd_compr_tstamp function in
    sound/core/compress_offload.c in the Linux kernel
    through 4.7, as used in Android before 2016-08-05 on
    Nexus 5 and 7 (2013) devices, does not properly
    initialize a timestamp data structure, which allows
    attackers to obtain sensitive information via a crafted
    application, aka Android internal bug 28770164 and
    Qualcomm internal bug CR568717.(CVE-2014-9892i1/4%0

  - A flaw was found in the way the Linux kernel's ext4
    file system handled the 'page size i1/4z block size'
    condition when the fallocate zero range functionality
    was used. A local attacker could use this flaw to crash
    the system.(CVE-2015-0275i1/4%0

  - An information leak flaw was found in the way the Linux
    kernel's ISO9660 file system implementation accessed
    data on an ISO9660 image with RockRidge Extension
    Reference (ER) records. An attacker with physical
    access to the system could use this flaw to disclose up
    to 255 bytes of kernel memory.(CVE-2014-9584i1/4%0

  - The pivot_root implementation in fs/namespace.c in the
    Linux kernel through 3.17 does not properly interact
    with certain locations of a chroot directory, which
    allows local users to cause a denial of service
    (mount-tree loop) via . (dot) values in both arguments
    to the pivot_root system call.(CVE-2014-7970i1/4%0

  - arch/x86/kvm/emulate.c in the Linux kernel before
    4.8.12 does not properly initialize Code Segment (CS)
    in certain error cases, which allows local users to
    obtain sensitive information from kernel stack memory
    via a crafted application.(CVE-2016-9756i1/4%0

  - A flaw was found in the Linux kernel where the
    swiotlb_print_info() function in lib/swiotlb.c allows
    local users to obtain some kernel address information
    by reading the kernel log (dmesg). This address is not
    useful to commit a further attack.(CVE-2018-5953i1/4%0

  - A flaw was found in the way the Linux kernel's file
    system implementation handled rename operations in
    which the source was inside and the destination was
    outside of a bind mount. A privileged user inside a
    container could use this flaw to escape the bind mount
    and, potentially, escalate their privileges on the
    system.(CVE-2015-2925i1/4%0

  - A use-after-free fault in the Linux kernel's usbtv
    driver could allow an attacker to cause a denial of
    service (system crash), or have unspecified other
    impacts, by triggering failure of audio registration of
    USB hardware using the usbtv kernel
    module.(CVE-2017-17975i1/4%0

  - The mm subsystem in the Linux kernel through 4.10.10
    does not properly enforce the CONFIG_STRICT_DEVMEM
    protection mechanism, which allows local users to read
    or write to kernel memory locations in the first
    megabyte (and bypass slab-allocation access
    restrictions) via an application that opens the
    /dev/mem file, related to arch/x86/mm/init.c and
    drivers/char/mem.c.(CVE-2017-7889i1/4%0

  - A flaw was discovered in the way the kernel allows
    stackable filesystems to overlay. A local attacker who
    is able to mount filesystems can abuse this flaw to
    escalate privileges.(CVE-2014-9922i1/4%0

  - sound/core/timer.c in the Linux kernel before 4.4.1
    retains certain linked lists after a close or stop
    action, which allows local users to cause a denial of
    service (system crash) via a crafted ioctl call,
    related to the (1) snd_timer_close and (2)
    _snd_timer_stop functions.(CVE-2016-2548i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1524
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a641036f");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9922");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

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

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
