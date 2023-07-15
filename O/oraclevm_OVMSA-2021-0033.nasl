##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2021-0033.
##

include('compat.inc');

if (description)
{
  script_id(154015);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-28694",
    "CVE-2021-28695",
    "CVE-2021-28696",
    "CVE-2021-28697",
    "CVE-2021-28698",
    "CVE-2021-28701"
  );
  script_xref(name:"IAVB", value:"2021-B-0060-S");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2021-0033)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

  - IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains
    which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify
    regions of memory which should be left untranslated, which typically means these addresses should pass the
    translation phase unaltered. While these are typically device specific ACPI properties, they can also be
    specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed
    to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a
    discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-
    mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the
    identity mappings would be left in place, allowing a guest continued access to ranges of memory which it
    shouldn't have access to anymore (CVE-2021-28696). (CVE-2021-28694, CVE-2021-28695, CVE-2021-28696)

  - grant table v2 status pages may remain accessible after de-allocation Guest get permitted access to
    certain Xen-owned pages of memory. The majority of such pages remain allocated / associated with a guest
    for its entire lifetime. Grant table v2 status pages, however, get de-allocated when a guest switched
    (back) from v2 to v1. The freeing of such pages requires that the hypervisor know where in the guest these
    pages were mapped. The hypervisor tracks only one use within guest space, but racing requests from the
    guest to insert mappings of these pages may result in any of them to become mapped in multiple locations.
    Upon switching back from v2 to v1, the guest would then retain access to a page that was freed and perhaps
    re-used for other purposes. (CVE-2021-28697)

  - long running loops in grant table handling In order to properly monitor resource use, Xen maintains
    information on the grant mappings a domain may create to map grants offered by other domains. In the
    process of carrying out certain actions, Xen would iterate over all such entries, including ones which
    aren't in use anymore and some which may have been created but never used. If the number of entries for a
    given domain is large enough, this iterating of the entire table may tie up a CPU for too long, starving
    other domains or causing issues in the hypervisor itself. Note that a domain may map its own grants, i.e.
    there is no need for multiple domains to be involved here. A pair of cooperating guests may, however,
    cause the effects to be more severe. (CVE-2021-28698)

  - Another race in XENMAPSPACE_grant_table handling Guests are permitted access to certain Xen-owned pages of
    memory. The majority of such pages remain allocated / associated with a guest for its entire lifetime.
    Grant table v2 status pages, however, are de-allocated when a guest switches (back) from v2 to v1. Freeing
    such pages requires that the hypervisor enforce that no parallel request can result in the addition of a
    mapping of such a page to a guest. That enforcement was missing, allowing guests to retain access to pages
    that were freed and perhaps re-used for other purposes. Unfortunately, when XSA-379 was being prepared,
    this similar issue was not noticed. (CVE-2021-28701)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28694.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28695.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28696.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28697.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28698.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2021-28701.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2021-0033.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected xen / xen-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28697");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28701");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/12");

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
    {'reference':'xen-4.4.4-222.0.42.el6', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'xen-4.4.4-222'},
    {'reference':'xen-tools-4.4.4-222.0.42.el6', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'xen-tools-4.4.4-222'}
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
