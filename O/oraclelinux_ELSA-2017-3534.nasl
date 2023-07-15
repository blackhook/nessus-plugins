#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3534.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99160);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2013-7446",
    "CVE-2015-4700",
    "CVE-2015-5707",
    "CVE-2015-8569",
    "CVE-2016-3140",
    "CVE-2016-3672",
    "CVE-2016-4482",
    "CVE-2016-4485",
    "CVE-2016-4580",
    "CVE-2016-7425",
    "CVE-2016-8399",
    "CVE-2016-8633",
    "CVE-2016-8645",
    "CVE-2016-8646",
    "CVE-2016-9178",
    "CVE-2016-9588",
    "CVE-2016-9644",
    "CVE-2016-9793",
    "CVE-2016-10088",
    "CVE-2016-10142",
    "CVE-2017-2636",
    "CVE-2017-5970",
    "CVE-2017-6074",
    "CVE-2017-6345",
    "CVE-2017-7187"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2017-3534)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2017-3534 advisory.

  - The bpf_int_jit_compile function in arch/x86/net/bpf_jit_comp.c in the Linux kernel before 4.0.6 allows
    local users to cause a denial of service (system crash) by creating a packet filter and then loading
    crafted BPF instructions that trigger late convergence by the JIT compiler. (CVE-2015-4700)

  - The sg implementation in the Linux kernel through 4.9 does not properly restrict write operations in
    situations where the KERNEL_DS option is set, which allows local users to read or write to arbitrary
    kernel memory locations or cause a denial of service (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2016-9576. (CVE-2016-10088)

  - An elevation of privilege vulnerability in the kernel networking subsystem could enable a local malicious
    application to execute arbitrary code within the context of the kernel. This issue is rated as Moderate
    because it first requires compromising a privileged process and current compiler optimizations restrict
    access to the vulnerable code. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID:
    A-31349935. (CVE-2016-8399)

  - An issue was discovered in the IPv6 protocol specification, related to ICMP Packet Too Big (PTB) messages.
    (The scope of this CVE is all affected IPv6 implementations from all vendors.) The security implications
    of IP fragmentation have been discussed at length in [RFC6274] and [RFC7739]. An attacker can leverage the
    generation of IPv6 atomic fragments to trigger the use of fragmentation in an arbitrary IPv6 flow (in
    scenarios in which actual fragmentation of packets is not needed) and can subsequently perform any type of
    fragmentation-based attack against legacy IPv6 nodes that do not implement [RFC6946]. That is, employing
    fragmentation where not actually needed allows for fragmentation-based attack vectors to be employed,
    unnecessarily. We note that, unfortunately, even nodes that already implement [RFC6946] can be subject to
    DoS attacks as a result of the generation of IPv6 atomic fragments. Let us assume that Host A is
    communicating with Host B and that, as a result of the widespread dropping of IPv6 packets that contain
    extension headers (including fragmentation) [RFC7872], some intermediate node filters fragments between
    Host B and Host A. If an attacker sends a forged ICMPv6 PTB error message to Host B, reporting an MTU
    smaller than 1280, this will trigger the generation of IPv6 atomic fragments from that moment on (as
    required by [RFC2460]). When Host B starts sending IPv6 atomic fragments (in response to the received
    ICMPv6 PTB error message), these packets will be dropped, since we previously noted that IPv6 packets with
    extension headers were being dropped between Host B and Host A. Thus, this situation will result in a DoS
    scenario. Another possible scenario is that in which two BGP peers are employing IPv6 transport and they
    implement Access Control Lists (ACLs) to drop IPv6 fragments (to avoid control-plane attacks). If the
    aforementioned BGP peers drop IPv6 fragments but still honor received ICMPv6 PTB error messages, an
    attacker could easily attack the corresponding peering session by simply sending an ICMPv6 PTB message
    with a reported MTU smaller than 1280 bytes. Once the attack packet has been sent, the aforementioned
    routers will themselves be the ones dropping their own traffic. (CVE-2016-10142)

  - The sg_ioctl function in drivers/scsi/sg.c in the Linux kernel through 4.10.4 allows local users to cause
    a denial of service (stack-based buffer overflow) or possibly have unspecified other impact via a large
    command size in an SG_NEXT_CMD_LEN ioctl call, leading to out-of-bounds write access in the sg_write
    function. (CVE-2017-7187)

  - Race condition in drivers/tty/n_hdlc.c in the Linux kernel through 4.10.1 allows local users to gain
    privileges or cause a denial of service (double free) by setting the HDLC line discipline. (CVE-2017-2636)

  - arch/x86/kvm/vmx.c in the Linux kernel through 4.9 mismanages the #BP and #OF exceptions, which allows
    guest OS users to cause a denial of service (guest OS crash) by declining to handle an exception thrown by
    an L2 guest. (CVE-2016-9588)

  - The arcmsr_iop_message_xfer function in drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel through 4.8.2
    does not restrict a certain length field, which allows local users to gain privileges or cause a denial of
    service (heap-based buffer overflow) via an ARCMSR_MESSAGE_WRITE_WQBUFFER control code. (CVE-2016-7425)

  - The (1) pptp_bind and (2) pptp_connect functions in drivers/net/ppp/pptp.c in the Linux kernel through
    4.3.3 do not verify an address length, which allows local users to obtain sensitive information from
    kernel memory and bypass the KASLR protection mechanism via a crafted application. (CVE-2015-8569)

  - The x25_negotiate_facilities function in net/x25/x25_facilities.c in the Linux kernel before 4.5.5 does
    not properly initialize a certain data structure, which allows attackers to obtain sensitive information
    from kernel stack memory via an X.25 Call Request. (CVE-2016-4580)

  - drivers/firewire/net.c in the Linux kernel before 4.8.7, in certain unusual hardware configurations,
    allows remote attackers to execute arbitrary code via crafted fragmented packets. (CVE-2016-8633)

  - The arch_pick_mmap_layout function in arch/x86/mm/mmap.c in the Linux kernel through 4.5.2 does not
    properly randomize the legacy base address, which makes it easier for local users to defeat the intended
    restrictions on the ADDR_NO_RANDOMIZE flag, and bypass the ASLR protection mechanism for a setuid or
    setgid program, by disabling stack-consumption resource limits. (CVE-2016-3672)

  - The TCP stack in the Linux kernel before 4.8.10 mishandles skb truncation, which allows local users to
    cause a denial of service (system crash) via a crafted application that makes sendto system calls, related
    to net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c. (CVE-2016-8645)

  - The __get_user_asm_ex macro in arch/x86/include/asm/uaccess.h in the Linux kernel before 4.7.5 does not
    initialize a certain integer variable, which allows local users to obtain sensitive information from
    kernel stack memory by triggering failure of a get_user_ex call. (CVE-2016-9178)

  - The digi_port_init function in drivers/usb/serial/digi_acceleport.c in the Linux kernel before 4.5.1
    allows physically proximate attackers to cause a denial of service (NULL pointer dereference and system
    crash) via a crafted endpoints value in a USB device descriptor. (CVE-2016-3140)

  - The LLC subsystem in the Linux kernel before 4.9.13 does not ensure that a certain destructor exists in
    required circumstances, which allows local users to cause a denial of service (BUG_ON) or possibly have
    unspecified other impact via crafted system calls. (CVE-2017-6345)

  - The ipv4_pktinfo_prepare function in net/ipv4/ip_sockglue.c in the Linux kernel through 4.9.9 allows
    attackers to cause a denial of service (system crash) via (1) an application that makes crafted system
    calls or possibly (2) IPv4 traffic with invalid IP options. (CVE-2017-5970)

  - Integer overflow in the sg_start_req function in drivers/scsi/sg.c in the Linux kernel 2.6.x through 4.x
    before 4.1 allows local users to cause a denial of service or possibly have unspecified other impact via a
    large iov_count value in a write request. (CVE-2015-5707)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-3534.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8399");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.17.4.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.17.4.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6 / 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.8.13-118.17.4.el6uek', '3.8.13-118.17.4.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2017-3534');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.8';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'dtrace-modules-3.8.13-118.17.4.el6uek-0.4.5-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.17.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.17.4.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.17.4.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'},
    {'reference':'dtrace-modules-3.8.13-118.17.4.el7uek-0.4.5-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-3.8.13'},
    {'reference':'kernel-uek-debug-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-3.8.13'},
    {'reference':'kernel-uek-debug-devel-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-3.8.13'},
    {'reference':'kernel-uek-devel-3.8.13-118.17.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-3.8.13'},
    {'reference':'kernel-uek-doc-3.8.13-118.17.4.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-3.8.13'},
    {'reference':'kernel-uek-firmware-3.8.13-118.17.4.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-3.8.13'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-3.8.13-118.17.4.el6uek / dtrace-modules-3.8.13-118.17.4.el7uek / kernel-uek / etc');
}
