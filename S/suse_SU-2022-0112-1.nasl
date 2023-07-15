#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0112-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156809);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-44531",
    "CVE-2021-44532",
    "CVE-2021-44533",
    "CVE-2022-21824"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0112-1");
  script_xref(name:"IAVB", value:"2022-B-0002-S");

  script_name(english:"SUSE SLES15 Security Update : nodejs14 (SUSE-SU-2022:0112-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0112-1 advisory.

  - Accepting arbitrary Subject Alternative Name (SAN) types, unless a PKI is specifically defined to use a
    particular SAN type, can result in bypassing name-constrained intermediates. Node.js < 12.22.9, < 14.18.3,
    < 16.13.2, and < 17.3.1 was accepting URI SAN types, which PKIs are often not defined to use.
    Additionally, when a protocol allows URI SANs, Node.js did not match the URI correctly.Versions of Node.js
    with the fix for this disable the URI SAN type when checking a certificate against a hostname. This
    behavior can be reverted through the --security-revert command-line option. (CVE-2021-44531)

  - Node.js < 12.22.9, < 14.18.3, < 16.13.2, and < 17.3.1 converts SANs (Subject Alternative Names) to a
    string format. It uses this string to check peer certificates against hostnames when validating
    connections. The string format was subject to an injection vulnerability when name constraints were used
    within a certificate chain, allowing the bypass of these name constraints.Versions of Node.js with the fix
    for this escape SANs containing the problematic characters in order to prevent the injection. This
    behavior can be reverted through the --security-revert command-line option. (CVE-2021-44532)

  - Node.js < 12.22.9, < 14.18.3, < 16.13.2, and < 17.3.1 did not handle multi-value Relative Distinguished
    Names correctly. Attackers could craft certificate subjects containing a single-value Relative
    Distinguished Name that would be interpreted as a multi-value Relative Distinguished Name, for example, in
    order to inject a Common Name that would allow bypassing the certificate subject verification.Affected
    versions of Node.js that do not accept multi-value Relative Distinguished Names and are thus not
    vulnerable to such attacks themselves. However, third-party code that uses node's ambiguous presentation
    of certificate subjects may be vulnerable. (CVE-2021-44533)

  - Due to the formatting logic of the console.table() function it was not safe to allow user controlled
    input to be passed to the properties parameter while simultaneously passing a plain object with at least
    one property as the first parameter, which could be __proto__. The prototype pollution has very limited
    control, in that it only allows an empty string to be assigned to numerical keys of the object
    prototype.Node.js >= 12.22.9, >= 14.18.3, >= 16.13.2, and >= 17.3.1 use a null protoype for the object
    these properties are being assigned to. (CVE-2022-21824)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194514");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2022-January/021384.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21824");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs14, nodejs14-devel, nodejs14-docs and / or npm14 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21824");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'nodejs14-14.18.3-15.24.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'nodejs14-devel-14.18.3-15.24.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'nodejs14-docs-14.18.3-15.24.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']},
    {'reference':'npm14-14.18.3-15.24.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-web-scripting-release-15.3', 'sles-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs14 / nodejs14-devel / nodejs14-docs / npm14');
}
