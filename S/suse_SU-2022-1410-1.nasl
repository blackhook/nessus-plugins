#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1410-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160219);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2022-24675", "CVE-2022-27536", "CVE-2022-28327");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1410-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : go1.18 (SUSE-SU-2022:1410-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:1410-1 advisory.

  - encoding/pem in Go before 1.17.9 and 1.18.x before 1.18.1 has a Decode stack overflow via a large amount
    of PEM data. (CVE-2022-24675)

  - Certificate.Verify in crypto/x509 in Go 1.18.x before 1.18.1 can be caused to panic on macOS when
    presented with certain malformed certificates. This allows a remote TLS server to cause a TLS client to
    panic. (CVE-2022-27536)

  - The generic P-256 feature in crypto/elliptic in Go before 1.17.9 and 1.18.x before 1.18.1 allows a panic
    via long scalar input. (CVE-2022-28327)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198427");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-April/010838.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7147384");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28327");
  script_set_attribute(attribute:"solution", value:
"Update the affected go1.18, go1.18-doc and / or go1.18-race packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28327");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.18-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.18-race");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'go1.18-1.18.1-150000.1.11.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'go1.18-1.18.1-150000.1.11.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'go1.18-doc-1.18.1-150000.1.11.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'go1.18-doc-1.18.1-150000.1.11.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'go1.18-race-1.18.1-150000.1.11.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'go1.18-race-1.18.1-150000.1.11.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'go1.18-race-1.18.1-150000.1.11.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'go1.18-race-1.18.1-150000.1.11.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'go1.18-1.18.1-150000.1.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'go1.18-doc-1.18.1-150000.1.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'go1.18-race-1.18.1-150000.1.11.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'go1.18-race-1.18.1-150000.1.11.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'go1.18-1.18.1-150000.1.11.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.18-doc-1.18.1-150000.1.11.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.18-race-1.18.1-150000.1.11.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.18-race-1.18.1-150000.1.11.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'go1.18 / go1.18-doc / go1.18-race');
}
