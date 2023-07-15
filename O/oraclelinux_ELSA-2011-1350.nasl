#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-1350.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68364);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2011-1160",
    "CVE-2011-1745",
    "CVE-2011-1746",
    "CVE-2011-1833",
    "CVE-2011-2022",
    "CVE-2011-2484",
    "CVE-2011-2496",
    "CVE-2011-2521",
    "CVE-2011-2723",
    "CVE-2011-2898",
    "CVE-2011-2918"
  );
  script_bugtraq_id(
    46866,
    47321,
    47534,
    47535,
    47843,
    48383,
    48580,
    48802,
    48929,
    48986,
    49108,
    49152
  );
  script_xref(name:"RHSA", value:"2011:1350");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-1350)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2011-1350 advisory.

  - The tpm_open function in drivers/char/tpm/tpm.c in the Linux kernel before 2.6.39 does not initialize a
    certain buffer, which allows local users to obtain potentially sensitive information from kernel memory
    via unspecified vectors. (CVE-2011-1160)

  - Integer overflow in the agp_generic_insert_memory function in drivers/char/agp/generic.c in the Linux
    kernel before 2.6.38.5 allows local users to gain privileges or cause a denial of service (system crash)
    via a crafted AGPIOC_BIND agp_ioctl ioctl call. (CVE-2011-1745)

  - Multiple integer overflows in the (1) agp_allocate_memory and (2) agp_create_user_memory functions in
    drivers/char/agp/generic.c in the Linux kernel before 2.6.38.5 allow local users to trigger buffer
    overflows, and consequently cause a denial of service (system crash) or possibly have unspecified other
    impact, via vectors related to calls that specify a large number of memory pages. (CVE-2011-1746)

  - Race condition in the ecryptfs_mount function in fs/ecryptfs/main.c in the eCryptfs subsystem in the Linux
    kernel before 3.1 allows local users to bypass intended file permissions via a mount.ecryptfs_private
    mount with a mismatched uid. (CVE-2011-1833)

  - The agp_generic_remove_memory function in drivers/char/agp/generic.c in the Linux kernel before 2.6.38.5
    does not validate a certain start parameter, which allows local users to gain privileges or cause a denial
    of service (system crash) via a crafted AGPIOC_UNBIND agp_ioctl ioctl call, a different vulnerability than
    CVE-2011-1745. (CVE-2011-2022)

  - The add_del_listener function in kernel/taskstats.c in the Linux kernel 2.6.39.1 and earlier does not
    prevent multiple registrations of exit handlers, which allows local users to cause a denial of service
    (memory and CPU consumption), and bypass the OOM Killer, via a crafted application. (CVE-2011-2484)

  - Integer overflow in the vma_to_resize function in mm/mremap.c in the Linux kernel before 2.6.39 allows
    local users to cause a denial of service (BUG_ON and system crash) via a crafted mremap system call that
    expands a memory mapping. (CVE-2011-2496)

  - The x86_assign_hw_event function in arch/x86/kernel/cpu/perf_event.c in the Performance Events subsystem
    in the Linux kernel before 2.6.39 does not properly calculate counter values, which allows local users to
    cause a denial of service (panic) via the perf program. (CVE-2011-2521)

  - The skb_gro_header_slow function in include/linux/netdevice.h in the Linux kernel before 2.6.39.4, when
    Generic Receive Offload (GRO) is enabled, resets certain fields in incorrect situations, which allows
    remote attackers to cause a denial of service (system crash) via crafted network traffic. (CVE-2011-2723)

  - net/packet/af_packet.c in the Linux kernel before 2.6.39.3 does not properly restrict user-space access to
    certain packet data structures associated with VLAN Tag Control Information, which allows local users to
    obtain potentially sensitive information via a crafted application. (CVE-2011-2898)

  - The Performance Events subsystem in the Linux kernel before 3.1 does not properly handle event overflows
    associated with PERF_COUNT_SW_CPU_CLOCK events, which allows local users to cause a denial of service
    (system hang) via a crafted application. (CVE-2011-2918)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-1350.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
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
  var fixed_uptrack_levels = ['2.6.32-131.17.1.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-1350');
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
    {'reference':'kernel-2.6.32-131.17.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-2.6.32-131.17.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-debug-2.6.32-131.17.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-2.6.32-131.17.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-131.17.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-131.17.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-131.17.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-131.17.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-131.17.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-131.17.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'kernel-headers-2.6.32-131.17.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-131.17.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-2.6.32-131.17.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
