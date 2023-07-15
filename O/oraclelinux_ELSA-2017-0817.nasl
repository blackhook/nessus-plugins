#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-0817.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99074);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2016-2069",
    "CVE-2016-2384",
    "CVE-2016-6480",
    "CVE-2016-7042",
    "CVE-2016-7097",
    "CVE-2016-8399",
    "CVE-2016-9576",
    "CVE-2016-10088",
    "CVE-2016-10142",
    "CVE-2017-5551"
  );
  script_xref(name:"RHSA", value:"2017:0817");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2017-0817)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2017-0817 advisory.

  - Race condition in arch/x86/mm/tlb.c in the Linux kernel before 4.4.1 allows local users to gain privileges
    by triggering access to a paging structure by a different CPU. (CVE-2016-2069)

  - Double free vulnerability in the snd_usbmidi_create function in sound/usb/midi.c in the Linux kernel
    before 4.5 allows physically proximate attackers to cause a denial of service (panic) or possibly have
    unspecified other impact via vectors involving an invalid USB descriptor. (CVE-2016-2384)

  - Race condition in the ioctl_send_fib function in drivers/scsi/aacraid/commctrl.c in the Linux kernel
    through 4.7 allows local users to cause a denial of service (out-of-bounds access or system crash) by
    changing a certain size value, aka a double fetch vulnerability. (CVE-2016-6480)

  - The proc_keys_show function in security/keys/proc.c in the Linux kernel through 4.8.2, when the GNU
    Compiler Collection (gcc) stack protector is enabled, uses an incorrect buffer size for certain timeout
    data, which allows local users to cause a denial of service (stack memory corruption and panic) by reading
    the /proc/keys file. (CVE-2016-7042)

  - The blk_rq_map_user_iov function in block/blk-map.c in the Linux kernel before 4.8.14 does not properly
    restrict the type of iterator, which allows local users to read or write to arbitrary kernel memory
    locations or cause a denial of service (use-after-free) by leveraging access to a /dev/sg device.
    (CVE-2016-9576)

  - The sg implementation in the Linux kernel through 4.9 does not properly restrict write operations in
    situations where the KERNEL_DS option is set, which allows local users to read or write to arbitrary
    kernel memory locations or cause a denial of service (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2016-9576. (CVE-2016-10088)

  - The filesystem implementation in the Linux kernel through 4.8.2 preserves the setgid bit during a setxattr
    call, which allows local users to gain group privileges by leveraging the existence of a setgid program
    with restrictions on execute permissions. (CVE-2016-7097)

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-0817.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8399");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-696.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2017-0817');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-2.6.32-696.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-2.6.32-696.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-696.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-696.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-2.6.32-696.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-696.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-696.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-696.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-696.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-696.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-696.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'kernel-headers-2.6.32-696.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-696.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-2.6.32-696.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-696.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-696.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-abi-whitelists / kernel-debug / etc');
}
