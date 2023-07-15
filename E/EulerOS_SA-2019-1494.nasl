#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125100);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id(
    "CVE-2016-4569",
    "CVE-2016-4578",
    "CVE-2016-4580",
    "CVE-2016-4581",
    "CVE-2016-4794",
    "CVE-2016-4805",
    "CVE-2016-4913",
    "CVE-2016-4997",
    "CVE-2016-4998",
    "CVE-2016-5195",
    "CVE-2016-5696",
    "CVE-2016-5829",
    "CVE-2016-6136",
    "CVE-2016-6197",
    "CVE-2016-6198",
    "CVE-2016-6327",
    "CVE-2016-6480",
    "CVE-2016-6786",
    "CVE-2016-6787",
    "CVE-2016-6828",
    "CVE-2016-7039",
    "CVE-2016-7042",
    "CVE-2016-7097"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1494)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A vulnerability was found in Linux kernel. There is an
    information leak in file 'sound/core/timer.c' of the
    latest mainline Linux kernel, the stack object
    aEURoetreadaEUR has a total size of 32 bytes. It contains a
    8-bytes padding, which is not initialized but sent to
    user via copy_to_user(), resulting a kernel
    leak.(CVE-2016-4569)

  - A vulnerability was found in Linux kernel. There is an
    information leak in file sound/core/timer.c of the
    latest mainline Linux kernel. The stack object aEURoer1aEUR
    has a total size of 32 bytes. Its field aEURoeeventaEUR and
    aEURoevalaEUR both contain 4 bytes padding. These 8 bytes
    padding bytes are sent to user without being
    initialized.(CVE-2016-4578)

  - The x25_negotiate_facilities function in
    net/x25/x25_facilities.c in the Linux kernel before
    4.5.5 does not properly initialize a certain data
    structure, which allows attackers to obtain sensitive
    information from kernel stack memory via an X.25 Call
    Request.(CVE-2016-4580)

  - fs/pnode.c in the Linux kernel before 4.5.4 does not
    properly traverse a mount propagation tree in a certain
    case involving a slave mount, which allows local users
    to cause a denial of service (NULL pointer dereference
    and OOPS) via a crafted series of mount system
    calls.(CVE-2016-4581)

  - Use after free vulnerability was found in percpu using
    previously allocated memory in bpf. First
    __alloc_percpu_gfp() is called, then the memory is
    freed with free_percpu() which triggers async
    pcpu_balance_work and then pcpu_extend_area_map could
    use a chunk after it has been freed.(CVE-2016-4794)

  - Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    before 4.5.2 allows local users to cause a denial of
    service (memory corruption and system crash, or
    spinlock) or possibly have unspecified other impact by
    removing a network namespace, related to the
    ppp_register_net_channel and ppp_unregister_channel
    functions.(CVE-2016-4805)

  - A vulnerability was found in the Linux kernel. Payloads
    of NM entries are not supposed to contain NUL. When
    such entry is processed, only the part prior to the
    first NUL goes into the concatenation (i.e. the
    directory entry name being encoded by a bunch of NM
    entries). The process stops when the amount collected
    so far + the claimed amount in the current NM entry
    exceed 254. However, the value returned as the total
    length is the sum of *claimed* sizes, not the actual
    amount collected. And that's what will be passed to
    readdir() callback as the name length - 8Kb
    __copy_to_user() from a buffer allocated by
    __get_free_page().(CVE-2016-4913)

  - A flaw was discovered in processing setsockopt for 32
    bit processes on 64 bit systems. This flaw will allow
    attackers to alter arbitrary kernel memory when
    unloading a kernel module. This action is usually
    restricted to root-privileged users but can also be
    leveraged if the kernel is compiled with CONFIG_USER_NS
    and CONFIG_NET_NS and the user is granted elevated
    privileges.(CVE-2016-4997)

  - An out-of-bounds heap memory access leading to a Denial
    of Service, heap disclosure, or further impact was
    found in setsockopt(). The function call is normally
    restricted to root, however some processes with
    cap_sys_admin may also be able to trigger this flaw in
    privileged container environments.(CVE-2016-4998)

  - A race condition was found in the way the Linux
    kernel's memory subsystem handled the copy-on-write
    (COW) breakage of private read-only memory mappings. An
    unprivileged, local user could use this flaw to gain
    write access to otherwise read-only memory mappings and
    thus increase their privileges on the
    system.(CVE-2016-5195)

  - It was found that the RFC 5961 challenge ACK rate
    limiting as implemented in the Linux kernel's
    networking subsystem allowed an off-path attacker to
    leak certain information about a given connection by
    creating congestion on the global challenge ACK rate
    limit counter and then measuring the changes by probing
    packets. An off-path attacker could use this flaw to
    either terminate TCP connection and/or inject payload
    into non-secured TCP connection between two endpoints
    on the network.(CVE-2016-5696)

  - A heap-based buffer overflow vulnerability was found in
    the Linux kernel's hiddev driver. This flaw could allow
    a local attacker to corrupt kernel memory, possible
    privilege escalation or crashing the
    system.(CVE-2016-5829)

  - When creating audit records for parameters to executed
    children processes, an attacker can convince the Linux
    kernel audit subsystem can create corrupt records which
    may allow an attacker to misrepresent or evade logging
    of executing commands.(CVE-2016-6136)

  - It was found that the unlink and rename functionality
    in overlayfs did not verify the upper dentry for
    staleness. A local, unprivileged user could use the
    rename syscall on overlayfs on top of xfs to panic or
    crash the system.(CVE-2016-6197)

  - A flaw was found that the vfs_rename() function did not
    detect hard links on overlayfs. A local, unprivileged
    user could use the rename syscall on overlayfs on top
    of xfs to crash the system.(CVE-2016-6198)

  - System using the infiniband support module ib_srpt were
    vulnerable to a denial of service by system crash by a
    local attacker who is able to abort writes to a device
    using this initiator.(CVE-2016-6327)

  - A race condition flaw was found in the ioctl_send_fib()
    function in the Linux kernel's aacraid implementation.
    A local attacker could use this flaw to cause a denial
    of service (out-of-bounds access or system crash) by
    changing a certain size value.(CVE-2016-6480)

  - kernel/events/core.c in the performance subsystem in
    the Linux kernel before 4.0 mismanages locks during
    certain migrations, which allows local users to gain
    privileges via a crafted application, aka Android
    internal bug 30955111.(CVE-2016-6786)

  - kernel/events/core.c in the performance subsystem in
    the Linux kernel before 4.0 mismanages locks during
    certain migrations, which allows local users to gain
    privileges via a crafted application, aka Android
    internal bug 31095224.(CVE-2016-6787)

  - A use-after-free vulnerability was found in
    tcp_xmit_retransmit_queue and other tcp_* functions.
    This condition could allow an attacker to send an
    incorrect selective acknowledgment to existing
    connections, possibly resetting a
    connection.(CVE-2016-6828)

  - Linux kernel built with the 802.1Q/802.1ad
    VLAN(CONFIG_VLAN_8021Q) OR Virtual eXtensible Local
    Area Network(CONFIG_VXLAN) with Transparent Ethernet
    Bridging(TEB) GRO support, is vulnerable to a stack
    overflow issue. It could occur while receiving large
    packets via GRO path, as an unlimited recursion could
    unfold in both VLAN and TEB modules, leading to a stack
    corruption in the kernel.(CVE-2016-7039)

  - It was found that when the gcc stack protector was
    enabled, reading the /proc/keys file could cause a
    panic in the Linux kernel due to stack corruption. This
    happened because an incorrect buffer size was used to
    hold a 64-bit timeout value rendered as
    weeks.(CVE-2016-7042)

  - It was found that when file permissions were modified
    via chmod and the user modifying them was not in the
    owning group or capable of CAP_FSETID, the setgid bit
    would be cleared. Setting a POSIX ACL via setxattr sets
    the file permissions as well as the new ACL, but
    doesn't clear the setgid bit in a similar way. This
    could allow a local user to gain group privileges via
    certain setgid applications.(CVE-2016-7097)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1494
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e64722c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5829");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

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
