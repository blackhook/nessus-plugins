#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0089. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167480);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id(
    "CVE-2019-19447",
    "CVE-2020-14356",
    "CVE-2020-14381",
    "CVE-2020-16166",
    "CVE-2020-25211",
    "CVE-2020-29661",
    "CVE-2021-0512",
    "CVE-2021-3348",
    "CVE-2021-3609",
    "CVE-2021-3715",
    "CVE-2021-4083",
    "CVE-2021-4155",
    "CVE-2021-22543",
    "CVE-2021-22555",
    "CVE-2021-23133",
    "CVE-2021-33033",
    "CVE-2021-37576",
    "CVE-2021-38201",
    "CVE-2022-0492",
    "CVE-2022-0847",
    "CVE-2022-27666"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2022-0089)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - In the Linux kernel 5.0.21, mounting a crafted ext4 filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in ext4_put_super in fs/ext4/super.c, related to dump_orphan_list
    in fs/ext4/super.c. (CVE-2019-19447)

  - A flaw null pointer dereference in the Linux kernel cgroupv2 subsystem in versions before 5.7.10 was found
    in the way when reboot the system. A local user could use this flaw to crash the system or escalate their
    privileges on the system. (CVE-2020-14356)

  - A flaw was found in the Linux kernel's futex implementation. This flaw allows a local attacker to corrupt
    system memory or escalate their privileges when creating a futex on a filesystem that is about to be
    unmounted. The highest threat from this vulnerability is to confidentiality, integrity, as well as system
    availability. (CVE-2020-14381)

  - The Linux kernel through 5.7.11 allows remote attackers to make observations that help to obtain sensitive
    information about the internal state of the network RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and kernel/time/timer.c. (CVE-2020-16166)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

  - In __hidinput_change_resolution_multipliers of hid-input.c, there is a possible out of bounds write due to
    a heap buffer overflow. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-173843328References: Upstream kernel (CVE-2021-0512)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

  - A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c.
    This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name
    space (CVE-2021-22555)

  - A race condition in Linux kernel SCTP sockets (net/sctp/socket.c) before 5.12-rc8 can lead to kernel
    privilege escalation from the context of a network service or an unprivileged process. If
    sctp_destroy_sock is called without sock_net(sk)->sctp.addr_wq_lock then an element is removed from the
    auto_asconf_splist list without any proper locking. This can be exploited by an attacker with network
    service privileges to escalate to root or from the context of an unprivileged user directly if a
    BPF_CGROUP_INET_SOCK_CREATE is attached which denies creation of some SCTP socket. (CVE-2021-23133)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

  - nbd_add_socket in drivers/block/nbd.c in the Linux kernel through 5.10.12 has an ndb_queue_rq use-after-
    free that could be triggered by local attackers (with access to the nbd device) via an I/O request at a
    certain point during device setup, aka CID-b98e762e3d71. (CVE-2021-3348)

  - .A flaw was found in the CAN BCM networking protocol in the Linux kernel, where a local attacker can abuse
    a flaw in the CAN subsystem to corrupt memory, crash the system or escalate privileges. This race
    condition in net/can/bcm.c in the Linux kernel allows for local privilege escalation to root.
    (CVE-2021-3609)

  - A flaw was found in the Routing decision classifier in the Linux kernel's Traffic Control networking
    subsystem in the way it handled changing of classification filters, leading to a use-after-free condition.
    This flaw allows unprivileged local users to escalate their privileges on the system. The highest threat
    from this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-3715)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - net/sunrpc/xdr.c in the Linux kernel before 5.13.4 allows remote attackers to cause a denial of service
    (xdr_set_page_base slab-out-of-bounds access) by performing many NFS 4.2 READ_PLUS operations.
    (CVE-2021-38201)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - A data leak flaw was found in the way XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for size
    increase of files with unaligned size. A local attacker could use this flaw to leak data on the XFS
    filesystem otherwise not accessible to them. (CVE-2021-4155)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A flaw was found in the way the flags member of the new pipe buffer structure was lacking proper
    initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus
    contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache
    backed by read only files and as such escalate their privileges on the system. (CVE-2022-0847)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0089");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-19447");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14356");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14381");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16166");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25211");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-29661");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-0512");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22543");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22555");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23133");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-33033");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3348");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3609");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3715");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-37576");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-38201");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-4083");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-4155");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0492");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0847");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-27666");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0847");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-27666");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.493.gfad234822'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
