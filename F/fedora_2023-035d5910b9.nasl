#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-035d5910b9
#

include('compat.inc');

if (description)
{
  script_id(174937);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/29");

  script_cve_id("CVE-2023-28626", "CVE-2023-28631");
  script_xref(name:"FEDORA", value:"2023-035d5910b9");

  script_name(english:"Fedora 38 : rust-askama / rust-askama_shared / rust-comrak (2023-035d5910b9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-035d5910b9 advisory.

  - comrak is a CommonMark + GFM compatible Markdown parser and renderer written in rust. A Comrak AST can be
    constructed manually by a program instead of parsing a Markdown document with `parse_document`. This AST
    can then be converted to HTML via `html::format_document_with_plugins`. However, the HTML formatting code
    assumes that the AST is well-formed. For example, many AST notes contain `[u8]` fields which the
    formatting code assumes is valid UTF-8 data. Several bugs can be triggered if this is not the case.
    Version 0.17.0 contains adjustments to the AST, storing strings instead of unvalidated byte arrays. Users
    are advised to upgrade. Users unable to upgrade may manually validate UTF-8 correctness of all data when
    assigning to `&[u8]` and `Vec<u8>` fields in the AST. This issue is also tracked as `GHSL-2023-049`.
    (CVE-2023-28631)

  - comrak is a CommonMark + GFM compatible Markdown parser and renderer written in rust. A range of quadratic
    parsing issues are present in Comrak. These can be used to craft denial-of-service attacks on services
    that use Comrak to parse Markdown. This issue has been addressed in version 0.17.0. Users are advised to
    upgrade. There are no known workarounds for this vulnerability. This issue is also tracked as
    `GHSL-2023-047` (CVE-2023-28626)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-035d5910b9");
  script_set_attribute(attribute:"solution", value:
"Update the affected rust-askama, rust-askama_shared and / or rust-comrak packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-askama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-askama_shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rust-comrak");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'rust-askama-0.11.1-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-askama_shared-0.12.2-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-comrak-0.18.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rust-askama / rust-askama_shared / rust-comrak');
}
