#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-2152.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87090);
  script_version("2.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2010-5313",
    "CVE-2013-7421",
    "CVE-2014-3647",
    "CVE-2014-7842",
    "CVE-2014-8171",
    "CVE-2014-9419",
    "CVE-2014-9644",
    "CVE-2015-0239",
    "CVE-2015-2925",
    "CVE-2015-3288",
    "CVE-2015-3339",
    "CVE-2015-4170",
    "CVE-2015-5283",
    "CVE-2015-6526",
    "CVE-2015-7553",
    "CVE-2015-7613",
    "CVE-2015-7837",
    "CVE-2015-8215",
    "CVE-2016-0774"
  );
  script_xref(name:"RHSA", value:"2015:2152");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2015-2152)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2015-2152 advisory.

  - The Crypto API in the Linux kernel before 3.18.5 allows local users to load arbitrary kernel modules via a
    bind system call for an AF_ALG socket with a module name in the salg_name field, a different vulnerability
    than CVE-2014-9644. (CVE-2013-7421)

  - The Crypto API in the Linux kernel before 3.18.5 allows local users to load arbitrary kernel modules via a
    bind system call for an AF_ALG socket with a parenthesized module template expression in the salg_name
    field, as demonstrated by the vfat(aes) expression, a different vulnerability than CVE-2013-7421.
    (CVE-2014-9644)

  - The memory resource controller (aka memcg) in the Linux kernel allows local users to cause a denial of
    service (deadlock) by spawning new processes within a memory-constrained cgroup. (CVE-2014-8171)

  - The __switch_to function in arch/x86/kernel/process_64.c in the Linux kernel through 3.18.1 does not
    ensure that Thread Local Storage (TLS) descriptors are loaded before proceeding with other steps, which
    makes it easier for local users to bypass the ASLR protection mechanism via a crafted application that
    reads a TLS base address. (CVE-2014-9419)

  - The em_sysenter function in arch/x86/kvm/emulate.c in the Linux kernel before 3.18.5, when the guest OS
    lacks SYSENTER MSR initialization, allows guest OS users to gain guest OS privileges or cause a denial of
    service (guest OS crash) by triggering use of a 16-bit code segment for emulation of a SYSENTER
    instruction. (CVE-2015-0239)

  - Race condition in the prepare_binprm function in fs/exec.c in the Linux kernel before 3.19.6 allows local
    users to gain privileges by executing a setuid program at a time instant when a chown to root is in
    progress, and the ownership is changed but the setuid bit is not yet stripped. (CVE-2015-3339)

  - Race condition in arch/x86/kvm/x86.c in the Linux kernel before 2.6.38 allows L2 guest OS users to cause a
    denial of service (L1 guest OS crash) via a crafted instruction that triggers an L2 emulation failure
    report, a similar issue to CVE-2014-7842. (CVE-2010-5313)

  - arch/x86/kvm/emulate.c in the KVM subsystem in the Linux kernel through 3.17.2 does not properly perform
    RIP changes, which allows guest OS users to cause a denial of service (guest OS crash) via a crafted
    application. (CVE-2014-3647)

  - Race condition in arch/x86/kvm/x86.c in the Linux kernel before 3.17.4 allows guest OS users to cause a
    denial of service (guest OS crash) via a crafted application that performs an MMIO transaction or a PIO
    transaction to trigger a guest userspace emulation error report, a similar issue to CVE-2010-5313.
    (CVE-2014-7842)

  - The prepend_path function in fs/dcache.c in the Linux kernel before 4.2.4 does not properly handle rename
    actions inside a bind mount, which allows local users to bypass an intended container protection mechanism
    by renaming a directory, related to a double-chroot attack. (CVE-2015-2925)

  - Race condition in the ldsem_cmpxchg function in drivers/tty/tty_ldsem.c in the Linux kernel before
    3.13-rc4-next-20131218 allows local users to cause a denial of service (ldsem_down_read and
    ldsem_down_write deadlock) by establishing a new tty thread during shutdown of a previous tty thread.
    (CVE-2015-4170)

  - The sctp_init function in net/sctp/protocol.c in the Linux kernel before 4.2.3 has an incorrect sequence
    of protocol-initialization steps, which allows local users to cause a denial of service (panic or memory
    corruption) by creating SCTP sockets before all of the steps have finished. (CVE-2015-5283)

  - The perf_callchain_user_64 function in arch/powerpc/perf/callchain.c in the Linux kernel before 4.0.2 on
    ppc64 platforms allows local users to cause a denial of service (infinite loop) via a deep 64-bit
    userspace backtrace. (CVE-2015-6526)

  - Race condition in the IPC object implementation in the Linux kernel through 4.2.3 allows local users to
    gain privileges by triggering an ipc_addid call that leads to uid and gid comparisons against
    uninitialized data, related to msg.c, shm.c, and util.c. (CVE-2015-7613)

  - The Linux kernel, as used in Red Hat Enterprise Linux 7, kernel-rt, and Enterprise MRG 2 and when booted
    with UEFI Secure Boot enabled, allows local users to bypass intended securelevel/secureboot restrictions
    by leveraging improper handling of secure_boot flag across kexec reboot. (CVE-2015-7837)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-2152.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/30");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['3.10.0-327.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2015-2152');
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
    {'reference':'kernel-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-327.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-327.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
