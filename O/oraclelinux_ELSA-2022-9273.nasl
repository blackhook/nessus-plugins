#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9273.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159642);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-36516",
    "CVE-2021-22600",
    "CVE-2021-26341",
    "CVE-2021-26401",
    "CVE-2022-0617",
    "CVE-2022-1016",
    "CVE-2022-1158",
    "CVE-2022-22942",
    "CVE-2022-23960",
    "CVE-2022-24448",
    "CVE-2022-26966"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel (ELSA-2022-9273)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2022-9273 advisory.

  - Some AMD CPUs may transiently execute beyond unconditional direct branches, which may potentially result
    in data leakage. (CVE-2021-26341)

  - LFENCE/JMP (mitigation V2-2) may not sufficiently mitigate CVE-2017-5715 on some AMD CPUs.
    (CVE-2021-26401)

  - Certain Arm Cortex and Neoverse processors through 2022-03-08 do not properly restrict cache speculation,
    aka Spectre-BHB. An attacker can leverage the shared branch history in the Branch History Buffer (BHB) to
    influence mispredicted branches. Then, cache allocation can allow the attacker to obtain sensitive
    information. (CVE-2022-23960)

  - An issue was discovered in the Linux kernel through 5.16.11. The mixed IPID assignment method with the
    hash-based IPID assignment policy allows an off-path attacker to inject data into a victim's TCP session
    or terminate that session. (CVE-2020-36516)

  - An issue was discovered in the Linux kernel before 5.16.12. drivers/net/usb/sr9700.c allows attackers to
    obtain sensitive information from heap memory via crafted frame lengths from a device. (CVE-2022-26966)

  - A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem.
    This flaw allows a local user to cause an out-of-bounds write issue. (CVE-2022-1015) (CVE-2022-1016)

  - A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through
    crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected
    versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755 (CVE-2021-22600)

  - A flaw null pointer dereference in the Linux kernel UDF file system functionality was found in the way
    user triggers udf_file_write_iter function for the malicious UDF image. A local user could use this flaw
    to crash the system. Actual from Linux kernel 4.2-rc1 till 5.17-rc2. (CVE-2022-0617)

  - An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5. If an application sets the
    O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a
    regular file is found, ENOTDIR should occur, but the server instead returns uninitialized data in the file
    descriptor. (CVE-2022-24448)

  - kernel: failing usercopy allows for use-after-free exploitation (CVE-2022-22942)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9273.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22600");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1158");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7 / 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.306.1.3.el7uek', '5.4.17-2136.306.1.3.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-9273');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.4';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-5.4.17-2136.306.1.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.306.1.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.306.1.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.306.1.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.306.1.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.306.1.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.306.1.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.306.1.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.306.1.3.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.306.1.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.306.1.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.306.1.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.306.1.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-5.4.17-2136.306.1.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-5.4.17-2136.306.1.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.306.1.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.306.1.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.306.1.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.306.1.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.306.1.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.306.1.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.306.1.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.306.1.3.el8uek', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
