#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124815);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-0728",
    "CVE-2016-0758",
    "CVE-2016-0821",
    "CVE-2016-0823",
    "CVE-2016-10044",
    "CVE-2016-10088",
    "CVE-2016-10200",
    "CVE-2016-10208",
    "CVE-2016-10229",
    "CVE-2016-1575",
    "CVE-2016-1576",
    "CVE-2016-2053",
    "CVE-2016-2069",
    "CVE-2016-2070",
    "CVE-2016-2117",
    "CVE-2016-2184",
    "CVE-2016-2185",
    "CVE-2016-2186",
    "CVE-2016-2187",
    "CVE-2016-2188",
    "CVE-2016-2384",
    "CVE-2016-2543",
    "CVE-2016-2544"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1491)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A use-after-free flaw was found in the way the Linux
    kernel's key management subsystem handled keyring
    object reference counting in certain error path of the
    join_session_keyring() function. A local, unprivileged
    user could use this flaw to escalate their privileges
    on the system.(CVE-2016-0728)

  - A flaw was found in the way the Linux kernel's ASN.1
    DER decoder processed certain certificate files with
    tags of indefinite length. A local, unprivileged user
    could use a specially crafted X.509 certificate DER
    file to crash the system or, potentially, escalate
    their privileges on the system.(CVE-2016-0758)

  - The LIST_POISON feature in include/linux/poison.h in
    the Linux kernel before 4.3, as used in Android 6.0.1
    before 2016-03-01, does not properly consider the
    relationship to the mmap_min_addr value, which makes it
    easier for attackers to bypass a poison-pointer
    protection mechanism by triggering the use of an
    uninitialized list entry, aka Android internal bug
    26186802, a different vulnerability than
    CVE-2015-3636.(CVE-2016-0821)

  - The pagemap_open function in fs/proc/task_mmu.c in the
    Linux kernel before 3.19.3, as used in Android 6.0.1
    before 2016-03-01, allows local users to obtain
    sensitive physical-address information by reading a
    pagemap file, aka Android internal bug
    25739721.(CVE-2016-0823)

  - The aio_mount function in fs/aio.c in the Linux kernel
    does not properly restrict execute access, which makes
    it easier for local users to bypass intended SELinux
    W^X policy restrictions.(CVE-2016-10044)

  - It was found that the fix for CVE-2016-9576 was
    incomplete: the Linux kernel's sg implementation did
    not properly restrict write operations in situations
    where the KERNEL_DS option is set. A local attacker to
    read or write to arbitrary kernel memory locations or
    cause a denial of service (use-after-free) by
    leveraging write access to a /dev/sg
    device.(CVE-2016-10088)

  - A use-after-free flaw was found in the Linux kernel
    which enables a race condition in the L2TPv3 IP
    Encapsulation feature. A local user could use this flaw
    to escalate their privileges or crash the
    system.(CVE-2016-10200)

  - Mounting a crafted EXT4 image read-only leads to an
    attacker controlled memory corruption and
    SLAB-Out-of-Bounds reads.(CVE-2016-10208)

  - The Linux kernel allows remote attackers to execute
    arbitrary code via UDP traffic that triggers an unsafe
    second checksum calculation during execution of a recv
    system call with the MSG_PEEK flag. This may create a
    kernel panic or memory corruption leading to privilege
    escalation.(CVE-2016-10229)

  - The overlayfs implementation in the Linux kernel
    through 4.5.2 does not properly maintain POSIX ACL
    xattr data, which allows local users to gain privileges
    by leveraging a group-writable setgid
    directory.(CVE-2016-1575)

  - The overlayfs implementation in the Linux kernel
    through 4.5.2 does not properly restrict the mount
    namespace, which allows local users to gain privileges
    by mounting an overlayfs filesystem on top of a FUSE
    filesystem, and then executing a crafted setuid
    program.(CVE-2016-1576)

  - A syntax vulnerability was discovered in the kernel's
    ASN1.1 DER decoder, which could lead to memory
    corruption or a complete local denial of service
    through x509 certificate DER files. A local system user
    could use a specially created key file to trigger
    BUG_ON() in the public_key_verify_signature() function
    (crypto/asymmetric_keys/public_key.c), to cause a
    kernel panic and crash the system.(CVE-2016-2053)

  - A flaw was discovered in the way the Linux kernel dealt
    with paging structures. When the kernel invalidated a
    paging structure that was not in use locally, it could,
    in principle, race against another CPU that is
    switching to a process that uses the paging structure
    in question. A local user could use a thread running
    with a stale cached virtual-i1/4zphysical translation to
    potentially escalate their privileges if the
    translation in question were writable and the physical
    page got reused for something critical (for example, a
    page table).(CVE-2016-2069)

  - A divide-by-zero vulnerability was found in a way the
    kernel processes TCP connections. The error can occur
    if a connection starts another cwnd reduction phase by
    setting tp-i1/4zprior_cwnd to the current cwnd (0) in
    tcp_init_cwnd_reduction(). A remote, unauthenticated
    attacker could use this flaw to crash the kernel
    (denial of service).(CVE-2016-2070)

  - It was discovered that the atl2_probe() function in the
    Atheros L2 Ethernet driver in the Linux kernel
    incorrectly enabled scatter/gather I/O. A remote
    attacker could use this flaw to obtain potentially
    sensitive information from the kernel
    memory.(CVE-2016-2117)

  - The create_fixed_stream_quirk function in
    sound/usb/quirks.c in the snd-usb-audio driver in the
    Linux kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference or double free, and system crash) via a
    crafted endpoints value in a USB device
    descriptor.(CVE-2016-2184)

  - The ati_remote2_probe function in
    drivers/input/misc/ati_remote2.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2185)

  - The powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2186)

  - The gtco_probe function in drivers/input/tablet/gtco.c
    in the Linux kernel through 4.5.2 allows physically
    proximate attackers to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    endpoints value in a USB device
    descriptor.(CVE-2016-2187)

  - The iowarrior_probe function in
    drivers/usb/misc/iowarrior.c in the Linux kernel before
    4.5.1 allows physically proximate attackers to cause a
    denial of service (NULL pointer dereference and system
    crash) via a crafted endpoints value in a USB device
    descriptor.(CVE-2016-2188)

  - A flaw was found in the USB-MIDI Linux kernel driver: a
    double-free error could be triggered for the 'umidi'
    object. An attacker with physical access to the system
    could use this flaw to escalate their
    privileges.(CVE-2016-2384)

  - The snd_seq_ioctl_remove_events function in
    sound/core/seq/seq_clientmgr.c in the Linux kernel
    before 4.4.1 does not verify FIFO assignment before
    proceeding with FIFO clearing, which allows local users
    to cause a denial of service (NULL pointer dereference
    and OOPS) via a crafted ioctl call.(CVE-2016-2543)

  - Race condition in the queue_delete function in
    sound/core/seq/seq_queue.c in the Linux kernel before
    4.4.1 allows local users to cause a denial of service
    (use-after-free and system crash) by making an ioctl
    call at a certain time.(CVE-2016-2544)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1491
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d818220");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

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
