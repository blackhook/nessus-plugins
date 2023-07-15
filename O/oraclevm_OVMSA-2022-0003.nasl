##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2022-0003.
##

include('compat.inc');

if (description)
{
  script_id(156595);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2017-17044",
    "CVE-2017-17045",
    "CVE-2021-28705",
    "CVE-2021-28706",
    "CVE-2021-28709"
  );

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2022-0003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

  - An issue was discovered in Xen through 4.9.x allowing HVM guest OS users to cause a denial of service
    (infinite loop and host OS hang) by leveraging the mishandling of Populate on Demand (PoD) errors.
    (CVE-2017-17044)

  - An issue was discovered in Xen through 4.9.x allowing HVM guest OS users to gain privileges on the host
    OS, obtain sensitive information, or cause a denial of service (BUG and host OS crash) by leveraging the
    mishandling of Populate on Demand (PoD) Physical-to-Machine (P2M) errors. (CVE-2017-17045)

  - issues with partially successful P2M updates on x86 T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] x86 HVM and PVH guests may be
    started in populate-on-demand (PoD) mode, to provide a way for them to later easily have more memory
    assigned. Guests are permitted to control certain P2M aspects of individual pages via hypercalls. These
    hypercalls may act on ranges of pages specified via page orders (resulting in a power-of-2 number of
    pages). In some cases the hypervisor carries out the requests by splitting them into smaller chunks. Error
    handling in certain PoD cases has been insufficient in that in particular partial success of some
    operations was not properly accounted for. There are two code paths affected - page removal
    (CVE-2021-28705) and insertion of new pages (CVE-2021-28709). (We provide one patch which combines the fix
    to both issues.) (CVE-2021-28705, CVE-2021-28709)

  - guests may exceed their designated memory limit When a guest is permitted to have close to 16TiB of
    memory, it may be able to issue hypercalls to increase its memory allocation beyond the administrator
    established limit. This is a result of a calculation done with 32-bit precision, which may overflow. It
    would then only be the overflowed (and hence small) number which gets compared against the established
    upper bound. (CVE-2021-28706)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2017-17044.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2017-17045.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28705.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28706.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28709.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2022-0003.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected xen / xen-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'xen-4.4.4-222.0.45.el6', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'xen-4.4.4-222'},
    {'reference':'xen-tools-4.4.4-222.0.45.el6', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'xen-tools-4.4.4-222'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-tools');
}
