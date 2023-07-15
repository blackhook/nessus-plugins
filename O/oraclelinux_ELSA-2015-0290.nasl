#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-0290.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81800);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2013-2929",
    "CVE-2014-0181",
    "CVE-2014-0196",
    "CVE-2014-0206",
    "CVE-2014-1737",
    "CVE-2014-1738",
    "CVE-2014-1739",
    "CVE-2014-2568",
    "CVE-2014-2672",
    "CVE-2014-2673",
    "CVE-2014-2706",
    "CVE-2014-2851",
    "CVE-2014-3144",
    "CVE-2014-3145",
    "CVE-2014-3153",
    "CVE-2014-3181",
    "CVE-2014-3182",
    "CVE-2014-3184",
    "CVE-2014-3185",
    "CVE-2014-3186",
    "CVE-2014-3534",
    "CVE-2014-3611",
    "CVE-2014-3631",
    "CVE-2014-3646",
    "CVE-2014-3673",
    "CVE-2014-3687",
    "CVE-2014-3688",
    "CVE-2014-3690",
    "CVE-2014-3917",
    "CVE-2014-3940",
    "CVE-2014-4027",
    "CVE-2014-4171",
    "CVE-2014-4652",
    "CVE-2014-4653",
    "CVE-2014-4654",
    "CVE-2014-4655",
    "CVE-2014-4656",
    "CVE-2014-4667",
    "CVE-2014-4699",
    "CVE-2014-4943",
    "CVE-2014-5045",
    "CVE-2014-5077",
    "CVE-2014-5471",
    "CVE-2014-5472",
    "CVE-2014-6410",
    "CVE-2014-6416",
    "CVE-2014-7145",
    "CVE-2014-7825",
    "CVE-2014-7826",
    "CVE-2014-7841",
    "CVE-2014-8086",
    "CVE-2014-8884",
    "CVE-2014-9322"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2015-0290)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2015-0290 advisory.

  - arch/x86/kvm/vmx.c in the KVM subsystem in the Linux kernel before 3.17.2 on Intel processors does not
    ensure that the value in the CR4 control register remains the same after a VM entry, which allows host OS
    users to kill arbitrary processes or cause a denial of service (system disruption) by leveraging /dev/kvm
    access, as demonstrated by PR_SET_TSC prctl calls within a modified copy of QEMU. (CVE-2014-3690)

  - The Linux kernel through 3.14.5 does not properly consider the presence of hugetlb entries, which allows
    local users to cause a denial of service (memory corruption or system crash) by accessing certain memory
    locations, as demonstrated by triggering a race condition via numa_maps read operations during hugepage
    migration, related to fs/proc/task_mmu.c and mm/mempolicy.c. (CVE-2014-3940)

  - kernel/trace/trace_syscalls.c in the Linux kernel through 3.17.2 does not properly handle private syscall
    numbers during use of the perf subsystem, which allows local users to cause a denial of service (out-of-
    bounds read and OOPS) or bypass the ASLR protection mechanism via a crafted application. (CVE-2014-7825)

  - kernel/trace/trace_syscalls.c in the Linux kernel through 3.17.2 does not properly handle private syscall
    numbers during use of the ftrace subsystem, which allows local users to gain privileges or cause a denial
    of service (invalid pointer dereference) via a crafted application. (CVE-2014-7826)

  - Race condition in the ext4_file_write_iter function in fs/ext4/file.c in the Linux kernel through 3.17
    allows local users to cause a denial of service (file unavailability) via a combination of a write action
    and an F_SETFL fcntl operation for the O_DIRECT flag. (CVE-2014-8086)

  - net/netfilter/nf_conntrack_proto_generic.c in the Linux kernel before 3.18 generates incorrect conntrack
    entries during handling of certain iptables rule sets for the SCTP, DCCP, GRE, and UDP-Lite protocols,
    which allows remote attackers to bypass intended access restrictions via packets with disallowed port
    numbers. (CVE-2014-8160)

  - The filesystem implementation in the Linux kernel before 3.13 performs certain operations on lists of
    files with an inappropriate locking approach, which allows local users to cause a denial of service (soft
    lockup or system crash) via unspecified use of Asynchronous I/O (AIO) operations. (CVE-2014-8172)

  - The pmd_none_or_trans_huge_or_clear_bad function in include/asm-generic/pgtable.h in the Linux kernel
    before 3.13 on NUMA systems does not properly determine whether a Page Middle Directory (PMD) entry is a
    transparent huge-table entry, which allows local users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have unspecified other impact via a crafted MADV_WILLNEED
    madvise system call that leverages the absence of a page-table lock. (CVE-2014-8173)

  - The ieee80211_fragment function in net/mac80211/tx.c in the Linux kernel before 3.13.5 does not properly
    maintain a certain tail pointer, which allows remote attackers to obtain sensitive cleartext information
    by reading packets. (CVE-2014-8709)

  - Stack-based buffer overflow in the ttusbdecfe_dvbs_diseqc_send_master_cmd function in
    drivers/media/usb/ttusb-dec/ttusbdecfe.c in the Linux kernel before 3.17.4 allows local users to cause a
    denial of service (system crash) or possibly gain privileges via a large message length in an ioctl call.
    (CVE-2014-8884)

  - The XFS implementation in the Linux kernel before 3.15 improperly uses an old size value during remote
    attribute replacement, which allows local users to cause a denial of service (transaction overrun and data
    corruption) or possibly gain privileges by leveraging XFS filesystem access. (CVE-2015-0274)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-0290.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9322");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android Towelroot Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.10.0-229.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2015-0290');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.10';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-229.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-229.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
