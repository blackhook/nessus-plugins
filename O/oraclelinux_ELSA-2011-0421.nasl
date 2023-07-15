#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-0421.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68247);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2010-3296",
    "CVE-2010-4346",
    "CVE-2010-4526",
    "CVE-2010-4648",
    "CVE-2010-4655",
    "CVE-2010-4656",
    "CVE-2011-0521",
    "CVE-2011-0695",
    "CVE-2011-0710",
    "CVE-2011-0716",
    "CVE-2011-1478"
  );
  script_bugtraq_id(
    43221,
    45323,
    45661,
    45972,
    45986,
    46069,
    46322,
    46421,
    46433,
    46839,
    47056
  );
  script_xref(name:"RHSA", value:"2011:0421");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-0421)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2011-0421 advisory.

  - The cxgb_extension_ioctl function in drivers/net/cxgb3/cxgb3_main.c in the Linux kernel before 2.6.36-rc5
    does not properly initialize a certain structure member, which allows local users to obtain potentially
    sensitive information from kernel stack memory via a CHELSIO_GET_QSET_NUM ioctl call. (CVE-2010-3296)

  - The install_special_mapping function in mm/mmap.c in the Linux kernel before 2.6.37-rc6 does not make an
    expected security_file_mmap function call, which allows local users to bypass intended mmap_min_addr
    restrictions and possibly conduct NULL pointer dereference attacks via a crafted assembly-language
    application. (CVE-2010-4346)

  - Race condition in the sctp_icmp_proto_unreachable function in net/sctp/input.c in Linux kernel 2.6.11-rc2
    through 2.6.33 allows remote attackers to cause a denial of service (panic) via an ICMP unreachable
    message to a socket that is already locked by a user, which causes the socket to be freed and triggers
    list corruption, related to the sctp_wait_for_connect function. (CVE-2010-4526)

  - The orinoco_ioctl_set_auth function in drivers/net/wireless/orinoco/wext.c in the Linux kernel before
    2.6.37 does not properly implement a TKIP protection mechanism, which makes it easier for remote attackers
    to obtain access to a Wi-Fi network by reading Wi-Fi frames. (CVE-2010-4648)

  - net/core/ethtool.c in the Linux kernel before 2.6.36 does not initialize certain data structures, which
    allows local users to obtain potentially sensitive information from kernel heap memory by leveraging the
    CAP_NET_ADMIN capability for an ethtool ioctl call. (CVE-2010-4655)

  - The iowarrior_write function in drivers/usb/misc/iowarrior.c in the Linux kernel before 2.6.37 does not
    properly allocate memory, which might allow local users to trigger a heap-based buffer overflow, and
    consequently cause a denial of service or gain privileges, via a long report. (CVE-2010-4656)

  - The dvb_ca_ioctl function in drivers/media/dvb/ttpci/av7110_ca.c in the Linux kernel before 2.6.38-rc2
    does not check the sign of a certain integer field, which allows local users to cause a denial of service
    (memory corruption) or possibly have unspecified other impact via a negative value. (CVE-2011-0521)

  - Race condition in the cm_work_handler function in the InfiniBand driver (drivers/infiniband/core/cma.c) in
    Linux kernel 2.6.x allows remote attackers to cause a denial of service (panic) by sending an InfiniBand
    request while other request handlers are still running, which triggers an invalid pointer dereference.
    (CVE-2011-0695)

  - The task_show_regs function in arch/s390/kernel/traps.c in the Linux kernel before
    2.6.38-rc4-next-20110216 on the s390 platform allows local users to obtain the values of the registers of
    an arbitrary process by reading a status file under /proc/. (CVE-2011-0710)

  - The br_multicast_add_group function in net/bridge/br_multicast.c in the Linux kernel before 2.6.38, when a
    certain Ethernet bridge configuration is used, allows local users to cause a denial of service (memory
    corruption and system crash) by sending IGMP packets to a local interface. (CVE-2011-0716)

  - The napi_reuse_skb function in net/core/dev.c in the Generic Receive Offload (GRO) implementation in the
    Linux kernel before 2.6.38 does not reset the values of certain structure members, which might allow
    remote attackers to cause a denial of service (NULL pointer dereference) via a malformed VLAN frame.
    (CVE-2011-1478)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0421.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0521");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['2.6.32-71.24.1.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-0421');
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
    {'reference':'kernel-2.6.32-71.24.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-2.6.32-71.24.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-debug-2.6.32-71.24.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-2.6.32-71.24.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-71.24.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-71.24.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-71.24.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-71.24.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-71.24.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-71.24.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'kernel-headers-2.6.32-71.24.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-71.24.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-debug / kernel-debug-devel / etc');
}
