##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0073. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160769);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2020-14356",
    "CVE-2020-14381",
    "CVE-2020-25211",
    "CVE-2020-29661",
    "CVE-2021-3348",
    "CVE-2021-3612",
    "CVE-2021-22555",
    "CVE-2021-23133",
    "CVE-2021-33033",
    "CVE-2021-37576",
    "CVE-2021-38201"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2022-0073)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - A flaw null pointer dereference in the Linux kernel cgroupv2 subsystem in versions before 5.7.10 was found
    in the way when reboot the system. A local user could use this flaw to crash the system or escalate their
    privileges on the system. (CVE-2020-14356)

  - A flaw was found in the Linux kernel's futex implementation. This flaw allows a local attacker to corrupt
    system memory or escalate their privileges when creating a futex on a filesystem that is about to be
    unmounted. The highest threat from this vulnerability is to confidentiality, integrity, as well as system
    availability. (CVE-2020-14381)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

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

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - net/sunrpc/xdr.c in the Linux kernel before 5.13.4 allows remote attackers to cause a denial of service
    (xdr_set_page_base slab-out-of-bounds access) by performing many NFS 4.2 READ_PLUS operations.
    (CVE-2021-38201)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0073");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14356");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14381");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25211");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-29661");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22555");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23133");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-33033");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3348");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3612");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-37576");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-38201");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37576");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf-debuginfo");
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

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'bpftool-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-abi-whitelists-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-cross-headers-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debug-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debug-core-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debug-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debug-devel-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debug-modules-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debug-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debug-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-debuginfo-common-x86_64-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-ipaclones-internal-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-selftests-internal-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-sign-keys-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-tools-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'kernel-tools-libs-devel-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54',
    'python3-perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.419.27.g8dd645d54'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
