##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2021-0020.
##

include('compat.inc');

if (description)
{
  script_id(151049);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-0089",
    "CVE-2021-26313",
    "CVE-2021-28690",
    "CVE-2021-28692"
  );
  script_xref(name:"IAVB", value:"2021-B-0060-S");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2021-0020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

  - Observable response discrepancy in some Intel(R) Processors may allow an authorized user to potentially
    enable information disclosure via local access. (CVE-2021-0089)

  - Potential speculative code store bypass in all supported CPU products, in conjunction with software
    vulnerabilities relating to speculative execution of overwritten instructions, may cause an incorrect
    speculation and could result in data leakage. (CVE-2021-26313)

  - x86: TSX Async Abort protections not restored after S3 This issue relates to the TSX Async Abort
    speculative security vulnerability. Please see https://xenbits.xen.org/xsa/advisory-305.html for details.
    Mitigating TAA by disabling TSX (the default and preferred option) requires selecting a non-default
    setting in MSR_TSX_CTRL. This setting isn't restored after S3 suspend. (CVE-2021-28690)

  - inappropriate x86 IOMMU timeout detection / handling IOMMUs process commands issued to them in parallel
    with the operation of the CPU(s) issuing such commands. In the current implementation in Xen, asynchronous
    notification of the completion of such commands is not used. Instead, the issuing CPU spin-waits for the
    completion of the most recently issued command(s). Some of these waiting loops try to apply a timeout to
    fail overly-slow commands. The course of action upon a perceived timeout actually being detected is
    inappropriate: - on Intel hardware guests which did not originally cause the timeout may be marked as
    crashed, - on AMD hardware higher layer callers would not be notified of the issue, making them continue
    as if the IOMMU operation succeeded. (CVE-2021-28692)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-0089.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-26313.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28690.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28692.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2021-0020.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected xen / xen-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28692");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

var pkgs = [
    {'reference':'xen-4.4.4-222.0.40.el6', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'xen-4.4.4-222'},
    {'reference':'xen-tools-4.4.4-222.0.40.el6', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'xen-tools-4.4.4-222'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-tools');
}
