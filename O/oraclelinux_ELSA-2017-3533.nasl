#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3533.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99159);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2015-8952",
    "CVE-2016-3140",
    "CVE-2016-3672",
    "CVE-2016-3951",
    "CVE-2016-7097",
    "CVE-2016-7425",
    "CVE-2016-8399",
    "CVE-2016-8632",
    "CVE-2016-8633",
    "CVE-2016-8645",
    "CVE-2016-9178",
    "CVE-2016-9588",
    "CVE-2016-9644",
    "CVE-2016-9756",
    "CVE-2016-10088",
    "CVE-2016-10147",
    "CVE-2017-2596",
    "CVE-2017-2636",
    "CVE-2017-5897",
    "CVE-2017-5970",
    "CVE-2017-6001",
    "CVE-2017-6345",
    "CVE-2017-7187"
  );

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2017-3533)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2017-3533 advisory.

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

  - The sg_ioctl function in drivers/scsi/sg.c in the Linux kernel through 4.10.4 allows local users to cause
    a denial of service (stack-based buffer overflow) or possibly have unspecified other impact via a large
    command size in an SG_NEXT_CMD_LEN ioctl call, leading to out-of-bounds write access in the sg_write
    function. (CVE-2017-7187)

  - Race condition in drivers/tty/n_hdlc.c in the Linux kernel through 4.10.1 allows local users to gain
    privileges or cause a denial of service (double free) by setting the HDLC line discipline. (CVE-2017-2636)

  - crypto/mcryptd.c in the Linux kernel before 4.8.15 allows local users to cause a denial of service (NULL
    pointer dereference and system crash) by using an AF_ALG socket with an incompatible algorithm, as
    demonstrated by mcryptd(md5). (CVE-2016-10147)

  - arch/x86/kvm/vmx.c in the Linux kernel through 4.9 mismanages the #BP and #OF exceptions, which allows
    guest OS users to cause a denial of service (guest OS crash) by declining to handle an exception thrown by
    an L2 guest. (CVE-2016-9588)

  - The arcmsr_iop_message_xfer function in drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel through 4.8.2
    does not restrict a certain length field, which allows local users to gain privileges or cause a denial of
    service (heap-based buffer overflow) via an ARCMSR_MESSAGE_WRITE_WQBUFFER control code. (CVE-2016-7425)

  - drivers/firewire/net.c in the Linux kernel before 4.8.7, in certain unusual hardware configurations,
    allows remote attackers to execute arbitrary code via crafted fragmented packets. (CVE-2016-8633)

  - Double free vulnerability in drivers/net/usb/cdc_ncm.c in the Linux kernel before 4.5 allows physically
    proximate attackers to cause a denial of service (system crash) or possibly have unspecified other impact
    by inserting a USB device with an invalid USB descriptor. (CVE-2016-3951)

  - The arch_pick_mmap_layout function in arch/x86/mm/mmap.c in the Linux kernel through 4.5.2 does not
    properly randomize the legacy base address, which makes it easier for local users to defeat the intended
    restrictions on the ADDR_NO_RANDOMIZE flag, and bypass the ASLR protection mechanism for a setuid or
    setgid program, by disabling stack-consumption resource limits. (CVE-2016-3672)

  - The nested_vmx_check_vmptr function in arch/x86/kvm/vmx.c in the Linux kernel through 4.9.8 improperly
    emulates the VMXON instruction, which allows KVM L1 guest OS users to cause a denial of service (host OS
    memory consumption) by leveraging the mishandling of page references. (CVE-2017-2596)

  - arch/x86/kvm/emulate.c in the Linux kernel before 4.8.12 does not properly initialize Code Segment (CS) in
    certain error cases, which allows local users to obtain sensitive information from kernel stack memory via
    a crafted application. (CVE-2016-9756)

  - The TCP stack in the Linux kernel before 4.8.10 mishandles skb truncation, which allows local users to
    cause a denial of service (system crash) via a crafted application that makes sendto system calls, related
    to net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c. (CVE-2016-8645)

  - The tipc_msg_build function in net/tipc/msg.c in the Linux kernel through 4.8.11 does not validate the
    relationship between the minimum fragment length and the maximum packet size, which allows local users to
    gain privileges or cause a denial of service (heap-based buffer overflow) by leveraging the CAP_NET_ADMIN
    capability. (CVE-2016-8632)

  - The __get_user_asm_ex macro in arch/x86/include/asm/uaccess.h in the Linux kernel before 4.7.5 does not
    initialize a certain integer variable, which allows local users to obtain sensitive information from
    kernel stack memory by triggering failure of a get_user_ex call. (CVE-2016-9178)

  - The mbcache feature in the ext2 and ext4 filesystem implementations in the Linux kernel before 4.6
    mishandles xattr block caching, which allows local users to cause a denial of service (soft lockup) via
    filesystem operations in environments that use many attributes, as demonstrated by Ceph and Samba.
    (CVE-2015-8952)

  - The digi_port_init function in drivers/usb/serial/digi_acceleport.c in the Linux kernel before 4.5.1
    allows physically proximate attackers to cause a denial of service (NULL pointer dereference and system
    crash) via a crafted endpoints value in a USB device descriptor. (CVE-2016-3140)

  - The LLC subsystem in the Linux kernel before 4.9.13 does not ensure that a certain destructor exists in
    required circumstances, which allows local users to cause a denial of service (BUG_ON) or possibly have
    unspecified other impact via crafted system calls. (CVE-2017-6345)

  - The ipv4_pktinfo_prepare function in net/ipv4/ip_sockglue.c in the Linux kernel through 4.9.9 allows
    attackers to cause a denial of service (system crash) via (1) an application that makes crafted system
    calls or possibly (2) IPv4 traffic with invalid IP options. (CVE-2017-5970)

  - Race condition in kernel/events/core.c in the Linux kernel before 4.9.7 allows local users to gain
    privileges via a crafted application that makes concurrent perf_event_open system calls for moving a
    software group into a hardware context. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2016-6786. (CVE-2017-6001)

  - The ip6gre_err function in net/ipv6/ip6_gre.c in the Linux kernel allows remote attackers to have
    unspecified impact via vectors involving GRE flags in an IPv6 packet, which trigger an out-of-bounds
    access. (CVE-2017-5897)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-3533.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6001");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-61.1.33.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-4.1.12-61.1.33.el7uek");
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
  var fixed_uptrack_levels = ['4.1.12-61.1.33.el6uek', '4.1.12-61.1.33.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2017-3533');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.1';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'dtrace-modules-4.1.12-61.1.33.el6uek-0.5.3-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-4.1.12-61.1.33.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-61.1.33.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-61.1.33.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-61.1.33.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-61.1.33.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-61.1.33.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'},
    {'reference':'dtrace-modules-4.1.12-61.1.33.el7uek-0.5.3-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-4.1.12-61.1.33.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-debug-4.1.12-61.1.33.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.1.12'},
    {'reference':'kernel-uek-debug-devel-4.1.12-61.1.33.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.1.12'},
    {'reference':'kernel-uek-devel-4.1.12-61.1.33.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.1.12'},
    {'reference':'kernel-uek-doc-4.1.12-61.1.33.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-61.1.33.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dtrace-modules-4.1.12-61.1.33.el6uek / dtrace-modules-4.1.12-61.1.33.el7uek / kernel-uek / etc');
}
