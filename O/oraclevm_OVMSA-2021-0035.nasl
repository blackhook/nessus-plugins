#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2021-0035.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154016);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-11089",
    "CVE-2017-18216",
    "CVE-2018-9517",
    "CVE-2019-3900",
    "CVE-2019-3901",
    "CVE-2019-10220",
    "CVE-2019-17133",
    "CVE-2019-19063",
    "CVE-2019-19066",
    "CVE-2019-19074",
    "CVE-2019-19448",
    "CVE-2020-12114",
    "CVE-2020-12771",
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26140",
    "CVE-2020-26141",
    "CVE-2020-26142",
    "CVE-2020-26143",
    "CVE-2020-26144",
    "CVE-2020-26145",
    "CVE-2020-26146",
    "CVE-2020-26147",
    "CVE-2020-27067",
    "CVE-2021-0512",
    "CVE-2021-0605",
    "CVE-2021-3612",
    "CVE-2021-3655",
    "CVE-2021-3679",
    "CVE-2021-3715",
    "CVE-2021-38160",
    "CVE-2021-40490"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"OracleVM 3.4 : kernel-uek (OVMSA-2021-0035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

  - In fs/ocfs2/cluster/nodemanager.c in the Linux kernel before 4.15, local users can cause a denial of
    service (NULL pointer dereference and BUG) because a required mutex is not used. (CVE-2017-18216)

  - In pppol2tp_connect, there is possible memory corruption due to a use after free. This could lead to local
    escalation of privilege with System execution privileges needed. User interaction is not needed for
    exploitation. Product: Android. Versions: Android kernel. Android ID: A-38159931. (CVE-2018-9517)

  - Linux kernel CIFS implementation, version 4.9.0 is vulnerable to a relative paths injection in directory
    entry lists. (CVE-2019-10220)

  - Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c in the
    Linux kernel through 5.3.11 allow attackers to cause a denial of service (memory consumption), aka
    CID-3f9361695113. (CVE-2019-19063)

  - A memory leak in the bfad_im_get_stats() function in drivers/scsi/bfa/bfad_attr.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    bfa_port_get_stats() failures, aka CID-0e62395da2bd. (CVE-2019-19066)

  - A memory leak in the ath9k_wmi_cmd() function in drivers/net/wireless/ath/ath9k/wmi.c in the Linux kernel
    through 5.3.11 allows attackers to cause a denial of service (memory consumption), aka CID-728c1e2a05e4.
    (CVE-2019-19074)

  - A race condition in perf_event_open() allows local attackers to leak sensitive data from setuid programs.
    As no relevant locks (in particular the cred_guard_mutex) are held during the ptrace_may_access() call, it
    is possible for the specified target task to perform an execve() syscall with setuid execution before
    perf_event_alloc() actually attaches to it, allowing an attacker to bypass the ptrace_may_access() check
    and the perf_event_exit_task(current) call that is performed in install_exec_creds() during privileged
    execve() calls. This issue affects kernel versions before 4.8. (CVE-2019-3901)

  - An issue was discovered in the Linux kernel through 5.6.11. btree_gc_coalesce in drivers/md/bcache/btree.c
    has a deadlock if a coalescing operation fails. (CVE-2020-12771)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2017-18216.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2018-9517.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2019-10220.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2019-19063.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2019-19066.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2019-19074.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2019-3901.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-12771.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2021-0035.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek / kernel-uek-firmware packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10220");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.1.12-124.56.1.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for OVMSA-2021-0035');
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
    {'reference':'kernel-uek-4.1.12-124.56.1.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.1.12'},
    {'reference':'kernel-uek-firmware-4.1.12-124.56.1.el6uek', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-4.1.12'}
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
  if (!empty_or_null(package_array['release'])) release = 'OVS' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-firmware');
}
