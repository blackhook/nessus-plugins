#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-3055.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85176);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2014-8133",
    "CVE-2014-9683",
    "CVE-2015-0239",
    "CVE-2015-3339"
  );

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2015-3055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2015-3055 advisory.

  - arch/x86/kernel/tls.c in the Thread Local Storage (TLS) implementation in the Linux kernel through 3.18.1
    allows local users to bypass the espfix protection mechanism, and consequently makes it easier for local
    users to bypass the ASLR protection mechanism, via a crafted application that makes a set_thread_area
    system call and later reads a 16-bit value. (CVE-2014-8133)

  - Off-by-one error in the ecryptfs_decode_from_filename function in fs/ecryptfs/crypto.c in the eCryptfs
    subsystem in the Linux kernel before 3.18.2 allows local users to cause a denial of service (buffer
    overflow and system crash) or possibly gain privileges via a crafted filename. (CVE-2014-9683)

  - The em_sysenter function in arch/x86/kvm/emulate.c in the Linux kernel before 3.18.5, when the guest OS
    lacks SYSENTER MSR initialization, allows guest OS users to gain guest OS privileges or cause a denial of
    service (guest OS crash) by triggering use of a 16-bit code segment for emulation of a SYSENTER
    instruction. (CVE-2015-0239)

  - Race condition in the prepare_binprm function in fs/exec.c in the Linux kernel before 3.19.6 allows local
    users to gain privileges by executing a setuid program at a time instant when a chown to root is in
    progress, and the ownership is changed but the setuid bit is not yet stripped. (CVE-2015-3339)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-3055.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.37.9.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.37.9.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.37.9.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.37.9.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.37.9.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.37.9.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.37.9.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.37.9.el6uekdebug");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5 / 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-400.37.9.el5uek', '2.6.32-400.37.9.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2015-3055');
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
    {'reference':'kernel-uek-2.6.32-400.37.9.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-2.6.32-400.37.9.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.37.9.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.37.9.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.37.9.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.37.9.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.37.9.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.37.9.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-400.37.9.el5uek', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-400.37.9.el5uek', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'mlnx_en-2.6.32-400.37.9.el5uek-1.5.7-2', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.37.9.el5uek-1.5.7-2', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.37.9.el5uekdebug-1.5.7-2', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.37.9.el5uekdebug-1.5.7-2', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.37.9.el5uek-1.5.1-4.0.58', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.37.9.el5uek-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.37.9.el5uekdebug-1.5.1-4.0.58', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.37.9.el5uekdebug-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-2.6.32-400.37.9.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-2.6.32-400.37.9.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.37.9.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.37.9.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.37.9.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.37.9.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.37.9.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.37.9.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-400.37.9.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-400.37.9.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'mlnx_en-2.6.32-400.37.9.el6uek-1.5.7-0.1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.37.9.el6uek-1.5.7-0.1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.37.9.el6uekdebug-1.5.7-0.1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.37.9.el6uekdebug-1.5.7-0.1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.37.9.el6uek-1.5.1-4.0.58', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.37.9.el6uek-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.37.9.el6uekdebug-1.5.1-4.0.58', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.37.9.el6uekdebug-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
