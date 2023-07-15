#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3451-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165559);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2022-36113", "CVE-2022-36114");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3451-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : rust1.62 (SUSE-SU-2022:3451-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3451-1 advisory.

  - Cargo is a package manager for the rust programming language. After a package is downloaded, Cargo
    extracts its source code in the ~/.cargo folder on disk, making it available to the Rust projects it
    builds. To record when an extraction is successful, Cargo writes ok to the .cargo-ok file at the root of
    the extracted source code once it extracted all the files. It was discovered that Cargo allowed packages
    to contain a .cargo-ok symbolic link, which Cargo would extract. Then, when Cargo attempted to write ok
    into .cargo-ok, it would actually replace the first two bytes of the file the symlink pointed to with ok.
    This would allow an attacker to corrupt one file on the machine using Cargo to extract the package. Note
    that by design Cargo allows code execution at build time, due to build scripts and procedural macros. The
    vulnerabilities in this advisory allow performing a subset of the possible damage in a harder to track
    down way. Your dependencies must still be trusted if you want to be protected from attacks, as it's
    possible to perform the same attacks with build scripts and procedural macros. The vulnerability is
    present in all versions of Cargo. Rust 1.64, to be released on September 22nd, will include a fix for it.
    Since the vulnerability is just a more limited way to accomplish what a malicious build scripts or
    procedural macros can do, we decided not to publish Rust point releases backporting the security fix.
    Patch files are available for Rust 1.63.0 are available in the wg-security-response repository for people
    building their own toolchain. Mitigations We recommend users of alternate registries to exercise care in
    which package they download, by only including trusted dependencies in their projects. Please note that
    even with these vulnerabilities fixed, by design Cargo allows arbitrary code execution at build time
    thanks to build scripts and procedural macros: a malicious dependency will be able to cause damage
    regardless of these vulnerabilities. crates.io implemented server-side checks to reject these kinds of
    packages years ago, and there are no packages on crates.io exploiting these vulnerabilities. crates.io
    users still need to exercise care in choosing their dependencies though, as remote code execution is
    allowed by design there as well. (CVE-2022-36113)

  - Cargo is a package manager for the rust programming language. It was discovered that Cargo did not limit
    the amount of data extracted from compressed archives. An attacker could upload to an alternate registry a
    specially crafted package that extracts way more data than its size (also known as a zip bomb),
    exhausting the disk space on the machine using Cargo to download the package. Note that by design Cargo
    allows code execution at build time, due to build scripts and procedural macros. The vulnerabilities in
    this advisory allow performing a subset of the possible damage in a harder to track down way. Your
    dependencies must still be trusted if you want to be protected from attacks, as it's possible to perform
    the same attacks with build scripts and procedural macros. The vulnerability is present in all versions of
    Cargo. Rust 1.64, to be released on September 22nd, will include a fix for it. Since the vulnerability is
    just a more limited way to accomplish what a malicious build scripts or procedural macros can do, we
    decided not to publish Rust point releases backporting the security fix. Patch files are available for
    Rust 1.63.0 are available in the wg-security-response repository for people building their own toolchain.
    We recommend users of alternate registries to excercise care in which package they download, by only
    including trusted dependencies in their projects. Please note that even with these vulnerabilities fixed,
    by design Cargo allows arbitrary code execution at build time thanks to build scripts and procedural
    macros: a malicious dependency will be able to cause damage regardless of these vulnerabilities. crates.io
    implemented server-side checks to reject these kinds of packages years ago, and there are no packages on
    crates.io exploiting these vulnerabilities. crates.io users still need to excercise care in choosing their
    dependencies though, as the same concerns about build scripts and procedural macros apply here.
    (CVE-2022-36114)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203433");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012440.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d2d4a4c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36114");
  script_set_attribute(attribute:"solution", value:
"Update the affected cargo1.62 and / or rust1.62 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36113");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cargo1.62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rust1.62");
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
if (os_ver == "SLED15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cargo1.62-1.62.1-150300.7.7.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'cargo1.62-1.62.1-150300.7.7.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'rust1.62-1.62.1-150300.7.7.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'rust1.62-1.62.1-150300.7.7.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'cargo1.62-1.62.1-150300.7.7.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'cargo1.62-1.62.1-150300.7.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'rust1.62-1.62.1-150300.7.7.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'rust1.62-1.62.1-150300.7.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'cargo1.62-1.62.1-150300.7.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'rust1.62-1.62.1-150300.7.7.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'cargo1.62-1.62.1-150300.7.7.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'rust1.62-1.62.1-150300.7.7.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cargo1.62 / rust1.62');
}
