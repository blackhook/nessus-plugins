#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0070. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127272);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2015-8830",
    "CVE-2016-3672",
    "CVE-2016-7913",
    "CVE-2017-0861",
    "CVE-2017-9725",
    "CVE-2017-10661",
    "CVE-2017-12154",
    "CVE-2017-12190",
    "CVE-2017-13305",
    "CVE-2017-15129",
    "CVE-2017-15265",
    "CVE-2017-15274",
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-17558",
    "CVE-2017-17805",
    "CVE-2017-18017",
    "CVE-2017-18203",
    "CVE-2017-18208",
    "CVE-2017-1000252",
    "CVE-2017-1000407",
    "CVE-2017-1000410",
    "CVE-2018-1120",
    "CVE-2018-1130",
    "CVE-2018-3646",
    "CVE-2018-5344",
    "CVE-2018-5750",
    "CVE-2018-5803",
    "CVE-2018-5848",
    "CVE-2018-7566",
    "CVE-2018-9568",
    "CVE-2018-17972",
    "CVE-2018-18397",
    "CVE-2018-18690",
    "CVE-2018-1000004",
    "CVE-2018-1000026"
  );
  script_bugtraq_id(102329);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2019-0070)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - Integer overflow in the aio_setup_single_vector function
    in fs/aio.c in the Linux kernel 4.0 allows local users
    to cause a denial of service or possibly have
    unspecified other impact via a large AIO iovec. NOTE:
    this vulnerability exists because of a CVE-2012-6701
    regression. (CVE-2015-8830)

  - A weakness was found in the Linux ASLR implementation.
    Any user able to running 32-bit applications in a x86
    machine can disable ASLR by setting the RLIMIT_STACK
    resource to unlimited. (CVE-2016-3672)

  - The xc2028_set_config function in
    drivers/media/tuners/tuner-xc2028.c in the Linux kernel
    before 4.6 allows local users to gain privileges or
    cause a denial of service (use-after-free) via vectors
    involving omission of the firmware name from a certain
    data structure. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely. (CVE-2016-7913)

  - Use-after-free vulnerability in the snd_pcm_info()
    function in the ALSA subsystem in the Linux kernel
    allows attackers to induce a kernel memory corruption
    and possibly crash or lock up a system. Due to the
    nature of the flaw, a privilege escalation cannot be
    fully ruled out, although we believe it is unlikely.
    (CVE-2017-0861)

  - A reachable assertion failure flaw was found in the
    Linux kernel built with KVM virtualisation(CONFIG_KVM)
    support with Virtual Function I/O feature (CONFIG_VFIO)
    enabled. This failure could occur if a malicious guest
    device sent a virtual interrupt (guest IRQ) with a
    larger (>1024) index value. (CVE-2017-1000252)

  - Linux kernel Virtualization Module (CONFIG_KVM) for the
    Intel processor family (CONFIG_KVM_INTEL) is vulnerable
    to a DoS issue. It could occur if a guest was to flood
    the I/O port 0x80 with write requests. A guest user
    could use this flaw to crash the host kernel resulting
    in DoS. (CVE-2017-1000407)

  - A flaw was found in the processing of incoming L2CAP
    bluetooth commands. Uninitialized stack variables can be
    sent to an attacker leaking data in kernel address
    space. (CVE-2017-1000410)

  - A race condition was found in the Linux kernel before
    version 4.11-rc1 in 'fs/timerfd.c' file which allows a
    local user to cause a kernel list corruption or use-
    after-free via simultaneous operations with a file
    descriptor which leverage improper 'might_cancel'
    queuing. An unprivileged local user could use this flaw
    to cause a denial of service of the system. Due to the
    nature of the flaw, privilege escalation cannot be fully
    ruled out, although we believe it is unlikely.
    (CVE-2017-10661)

  - Linux kernel built with the KVM visualization support
    (CONFIG_KVM), with nested visualization (nVMX) feature
    enabled (nested=1), is vulnerable to a crash due to
    disabled external interrupts. As L2 guest could access
    (r/w) hardware CR8 register of the host(L0). In a nested
    visualization setup, L2 guest user could use this flaw
    to potentially crash the host(L0) resulting in DoS.
    (CVE-2017-12154)

  - It was found that in the Linux kernel through v4.14-rc5,
    bio_map_user_iov() and bio_unmap_user() in 'block/bio.c'
    do unbalanced pages refcounting if IO vector has small
    consecutive buffers belonging to the same page.
    bio_add_pc_page() merges them into one, but the page
    reference is never dropped, causing a memory leak and
    possible system lockup due to out-of-memory condition.
    (CVE-2017-12190)

  - A flaw was found in the Linux kernel's implementation of
    valid_master_desc() in which a memory buffer would be
    compared to a userspace value with an incorrect size of
    comparison. By bruteforcing the comparison, an attacker
    could determine what was in memory after the description
    and possibly obtain sensitive information from kernel
    memory. (CVE-2017-13305)

  - A use-after-free vulnerability was found in a network
    namespaces code affecting the Linux kernel since
    v4.0-rc1 through v4.15-rc5. The function
    get_net_ns_by_id() does not check for the net::count
    value after it has found a peer network in netns_ids idr
    which could lead to double free and memory corruption.
    This vulnerability could allow an unprivileged local
    user to induce kernel memory corruption on the system,
    leading to a crash. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out, although
    it is thought to be unlikely. (CVE-2017-15129)

  - A use-after-free vulnerability was found when issuing an
    ioctl to a sound device. This could allow a user to
    exploit a race condition and create memory corruption or
    possibly privilege escalation. (CVE-2017-15265)

  - A flaw was found in the implementation of associative
    arrays where the add_key systemcall and KEYCTL_UPDATE
    operations allowed for a NULL payload with a nonzero
    length. When accessing the payload within this length
    parameters value, an unprivileged user could trivially
    cause a NULL pointer dereference (kernel oops).
    (CVE-2017-15274)

  - The net/netfilter/nfnetlink_cthelper.c function in the
    Linux kernel through 4.14.4 does not require the
    CAP_NET_ADMIN capability for new, get, and del
    operations. This allows local users to bypass intended
    access restrictions because the nfnl_cthelper_list data
    structure is shared across all net namespaces.
    (CVE-2017-17448)

  - The __netlink_deliver_tap_skb function in
    net/netlink/af_netlink.c in the Linux kernel, through
    4.14.4, does not restrict observations of Netlink
    messages to a single net namespace, when CONFIG_NLMON is
    enabled. This allows local users to obtain sensitive
    information by leveraging the CAP_NET_ADMIN capability
    to sniff an nlmon interface for all Netlink activity on
    the system. (CVE-2017-17449)

  - The usb_destroy_configuration() function, in
    'drivers/usb/core/config.c' in the USB core subsystem,
    in the Linux kernel through 4.14.5 does not consider the
    maximum number of configurations and interfaces before
    attempting to release resources. This allows local users
    to cause a denial of service, due to out-of-bounds write
    access, or possibly have unspecified other impact via a
    crafted USB device. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out, although
    we believe it is unlikely. (CVE-2017-17558)

  - The Salsa20 encryption algorithm in the Linux kernel,
    before 4.14.8, does not correctly handle zero-length
    inputs. This allows a local attacker the ability to use
    the AF_ALG-based skcipher interface to cause a denial of
    service (uninitialized-memory free and kernel crash) or
    have an unspecified other impact by executing a crafted
    sequence of system calls that use the blkcipher_walk
    API. Both the generic implementation
    (crypto/salsa20_generic.c) and x86 implementation
    (arch/x86/crypto/salsa20_glue.c) of Salsa20 are
    vulnerable. (CVE-2017-17805)

  - The tcpmss_mangle_packet function in
    net/netfilter/xt_TCPMSS.c in the Linux kernel before
    4.11, and 4.9.x before 4.9.36, allows remote attackers
    to cause a denial of service (use-after-free and memory
    corruption) or possibly have unspecified other impact by
    leveraging the presence of xt_TCPMSS in an iptables
    action. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely. (CVE-2017-18017)

  - The Linux kernel, before version 4.14.3, is vulnerable
    to a denial of service in
    drivers/md/dm.c:dm_get_from_kobject() which can be
    caused by local users leveraging a race condition with
    __dm_destroy() during creation and removal of DM
    devices. Only privileged local users (with CAP_SYS_ADMIN
    capability) can directly perform the ioctl operations
    for dm device creation and removal and this would
    typically be outside the direct control of the
    unprivileged attacker. (CVE-2017-18203)

  - The madvise_willneed function in the Linux kernel allows
    local users to cause a denial of service (infinite loop)
    by triggering use of MADVISE_WILLNEED for a DAX mapping.
    (CVE-2017-18208)

  - A flaw was found where the kernel truncated the value
    used to indicate the size of a buffer which it would
    later become zero using an untruncated value. This can
    corrupt memory outside of the original allocation.
    (CVE-2017-9725)

  - In the Linux kernel versions 4.12, 3.10, 2.6, and
    possibly earlier, a race condition vulnerability exists
    in the sound system allowing for a potential deadlock
    and memory corruption due to use-after-free condition
    and thus denial of service. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely. (CVE-2018-1000004)

  - Improper validation in the bnx2x network card driver of
    the Linux kernel version 4.15 can allow for denial of
    service (DoS) attacks via a packet with a gso_size
    larger than ~9700 bytes. Untrusted guest VMs can exploit
    this vulnerability in the host machine, causing a crash
    in the network card. (CVE-2018-1000026)

  - By mmap()ing a FUSE-backed file onto a process's memory
    containing command line arguments (or environment
    strings), an attacker can cause utilities from psutils
    or procps (such as ps, w) or any other program which
    makes a read() call to the /proc//cmdline (or
    /proc//environ) files to block indefinitely (denial
    of service) or for some controlled time (as a
    synchronization primitive for other attacks).
    (CVE-2018-1120)

  - A null pointer dereference in dccp_write_xmit() function
    in net/dccp/output.c in the Linux kernel allows a local
    user to cause a denial of service by a number of certain
    crafted system calls. (CVE-2018-1130)

  - An issue was discovered in the proc_pid_stack function
    in fs/proc/base.c in the Linux kernel. An attacker with
    a local account can trick the stack unwinder code to
    leak stack contents to userspace. The fix allows only
    root to inspect the kernel stack of an arbitrary task.
    (CVE-2018-17972)

  - A flaw was found in the Linux kernel with files on tmpfs
    and hugetlbfs. An attacker is able to bypass file
    permissions on filesystems mounted with tmpfs/hugetlbs
    to modify a file and possibly disrupt normal system
    behavior. At this time there is an understanding there
    is no crash or privilege escalation but the impact of
    modifications on these filesystems of files in
    production systems may have adverse affects.
    (CVE-2018-18397)

  - In the Linux kernel before 4.17, a local attacker able
    to set attributes on an xfs filesystem could make this
    filesystem non-operational until the next mount by
    triggering an unchecked error condition during an xfs
    attribute change, because xfs_attr_shortform_addname in
    fs/xfs/libxfs/xfs_attr.c mishandles ATTR_REPLACE
    operations with conversion of an attr from short to long
    form. (CVE-2018-18690)

  - Modern operating systems implement virtualization of
    physical memory to efficiently use available system
    resources and provide inter-domain protection through
    access control and isolation. The L1TF issue was found
    in the way the x86 microprocessor designs have
    implemented speculative execution of instructions (a
    commonly used performance optimization) in combination
    with handling of page-faults caused by terminated
    virtual to physical address resolving process. As a
    result, an unprivileged attacker could use this flaw to
    read privileged memory of the kernel or other processes
    and/or cross guest/host boundaries to read host memory
    by conducting targeted cache side-channel attacks.
    (CVE-2018-3646)

  - A flaw was found in the Linux kernel's handling of
    loopback devices. An attacker, who has permissions to
    setup loopback disks, may create a denial of service or
    other unspecified actions. (CVE-2018-5344)

  - The acpi_smbus_hc_add function in drivers/acpi/sbshc.c
    in the Linux kernel, through 4.14.15, allows local users
    to obtain sensitive address information by reading dmesg
    data from an SBS HC printk call. (CVE-2018-5750)

  - An error in the _sctp_make_chunk() function
    (net/sctp/sm_make_chunk.c) when handling SCTP, packet
    length can be exploited by a malicious local user to
    cause a kernel crash and a DoS. (CVE-2018-5803)

  - In the function wmi_set_ie() in the Linux kernel the
    length validation code does not handle unsigned integer
    overflow properly. As a result, a large value of the
    ie_len argument can cause a buffer overflow and thus a
    memory corruption leading to a system crash or other or
    unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out, although
    we believe it is unlikely. (CVE-2018-5848)

  - ALSA sequencer core initializes the event pool on demand
    by invoking snd_seq_pool_init() when the first write
    happens and the pool is empty. A user can reset the pool
    size manually via ioctl concurrently, and this may lead
    to UAF or out-of-bound access. (CVE-2018-7566)

  - A possible memory corruption due to a type confusion was
    found in the Linux kernel in the sk_clone_lock()
    function in the net/core/sock.c. The possibility of
    local escalation of privileges cannot be fully ruled out
    for a local unprivileged attacker. (CVE-2018-9568)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0070");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18017");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-core-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.322.gc3912fd.lite"
  ],
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-doc-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "perf-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "python-perf-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9",
    "python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.12.319.g46331d9"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
