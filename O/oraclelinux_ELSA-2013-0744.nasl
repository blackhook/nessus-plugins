#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-0744.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68807);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2012-6537",
    "CVE-2012-6538",
    "CVE-2012-6546",
    "CVE-2012-6547",
    "CVE-2013-0349",
    "CVE-2013-0913",
    "CVE-2013-1767",
    "CVE-2013-1773",
    "CVE-2013-1774",
    "CVE-2013-1792",
    "CVE-2013-1796",
    "CVE-2013-1797",
    "CVE-2013-1798",
    "CVE-2013-1826",
    "CVE-2013-1827"
  );
  script_bugtraq_id(
    58112,
    58177,
    58200,
    58202,
    58368,
    58381,
    58383,
    58427,
    58604,
    58605,
    58607,
    58977,
    58992,
    58996
  );
  script_xref(name:"RHSA", value:"2013:0744");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2013-0744)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2013-0744 advisory.

  - The kvm_set_msr_common function in arch/x86/kvm/x86.c in the Linux kernel through 3.8.4 does not ensure a
    required time_page alignment during an MSR_KVM_SYSTEM_TIME operation, which allows guest OS users to cause
    a denial of service (buffer overflow and host OS memory corruption) or possibly have unspecified other
    impact via a crafted application. (CVE-2013-1796)

  - Use-after-free vulnerability in arch/x86/kvm/x86.c in the Linux kernel through 3.8.4 allows guest OS users
    to cause a denial of service (host OS memory corruption) or possibly have unspecified other impact via a
    crafted application that triggers use of a guest physical address (GPA) in (1) movable or (2) removable
    memory during an MSR_KVM_SYSTEM_TIME kvm_set_msr_common operation. (CVE-2013-1797)

  - The ioapic_read_indirect function in virt/kvm/ioapic.c in the Linux kernel through 3.8.4 does not properly
    handle a certain combination of invalid IOAPIC_REG_SELECT and IOAPIC_REG_WINDOW operations, which allows
    guest OS users to obtain sensitive information from host OS memory or cause a denial of service (host OS
    OOPS) via a crafted application. (CVE-2013-1798)

  - Integer overflow in drivers/gpu/drm/i915/i915_gem_execbuffer.c in the i915 driver in the Direct Rendering
    Manager (DRM) subsystem in the Linux kernel through 3.8.3, as used in Google Chrome OS before
    25.0.1364.173 and other products, allows local users to cause a denial of service (heap-based buffer
    overflow) or possibly have unspecified other impact via a crafted application that triggers many
    relocation copies, and potentially leads to a race condition. (CVE-2013-0913)

  - Buffer overflow in the VFAT filesystem implementation in the Linux kernel before 3.3 allows local users to
    gain privileges or cause a denial of service (system crash) via a VFAT write operation on a filesystem
    with the utf8 mount option, which is not properly handled during UTF-8 to UTF-16 conversion.
    (CVE-2013-1773)

  - net/xfrm/xfrm_user.c in the Linux kernel before 3.6 does not initialize certain structures, which allows
    local users to obtain sensitive information from kernel memory by leveraging the CAP_NET_ADMIN capability.
    (CVE-2012-6537)

  - The ATM implementation in the Linux kernel before 3.6 does not initialize certain structures, which allows
    local users to obtain sensitive information from kernel stack memory via a crafted application.
    (CVE-2012-6546)

  - The __tun_chr_ioctl function in drivers/net/tun.c in the Linux kernel before 3.6 does not initialize a
    certain structure, which allows local users to obtain sensitive information from kernel stack memory via a
    crafted application. (CVE-2012-6547)

  - The xfrm_state_netlink function in net/xfrm/xfrm_user.c in the Linux kernel before 3.5.7 does not properly
    handle error conditions in dump_one_state function calls, which allows local users to gain privileges or
    cause a denial of service (NULL pointer dereference and system crash) by leveraging the CAP_NET_ADMIN
    capability. (CVE-2013-1826)

  - The hidp_setup_hid function in net/bluetooth/hidp/core.c in the Linux kernel before 3.7.6 does not
    properly copy a certain name field, which allows local users to obtain sensitive information from kernel
    memory by setting a long name and making an HIDPCONNADD ioctl call. (CVE-2013-0349)

  - Use-after-free vulnerability in the shmem_remount_fs function in mm/shmem.c in the Linux kernel before
    3.7.10 allows local users to gain privileges or cause a denial of service (system crash) by remounting a
    tmpfs filesystem without specifying a required mpol (aka mempolicy) mount option. (CVE-2013-1767)

  - The chase_port function in drivers/usb/serial/io_ti.c in the Linux kernel before 3.7.4 allows local users
    to cause a denial of service (NULL pointer dereference and system crash) via an attempted /dev/ttyUSB read
    or write operation on a disconnected Edgeport USB serial converter. (CVE-2013-1774)

  - Race condition in the install_user_keyrings function in security/keys/process_keys.c in the Linux kernel
    before 3.8.3 allows local users to cause a denial of service (NULL pointer dereference and system crash)
    via crafted keyctl system calls that trigger keyring operations in simultaneous threads. (CVE-2013-1792)

  - net/dccp/ccid.h in the Linux kernel before 3.5.4 allows local users to gain privileges or cause a denial
    of service (NULL pointer dereference and system crash) by leveraging the CAP_NET_ADMIN capability for a
    certain (1) sender or (2) receiver getsockopt call. (CVE-2013-1827)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0744.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0913");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/23");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
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
  var fixed_uptrack_levels = ['2.6.32-358.6.1.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2013-0744');
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
    {'reference':'kernel-2.6.32-358.6.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-2.6.32-358.6.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-debug-2.6.32-358.6.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-2.6.32-358.6.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-358.6.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-358.6.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-358.6.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-358.6.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-358.6.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-358.6.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'kernel-headers-2.6.32-358.6.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-358.6.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-2.6.32-358.6.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-358.6.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-358.6.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
