##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-1819.
##

include('compat.inc');

if (description)
{
  script_id(161286);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id(
    "CVE-2021-38297",
    "CVE-2021-39293",
    "CVE-2021-41771",
    "CVE-2021-41772",
    "CVE-2022-23772",
    "CVE-2022-23773",
    "CVE-2022-23806"
  );
  script_xref(name:"IAVB", value:"2022-B-0008-S");
  script_xref(name:"IAVB", value:"2021-B-0069-S");

  script_name(english:"Oracle Linux 8 : go-toolset:ol8 (ELSA-2022-1819)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-1819 advisory.

  - In archive/zip in Go before 1.16.8 and 1.17.x before 1.17.1, a crafted archive header (falsely designating
    that many files are present) can cause a NewReader or OpenReader panic. NOTE: this issue exists because of
    an incomplete fix for CVE-2021-33196. (CVE-2021-39293)

  - Go before 1.16.10 and 1.17.x before 1.17.3 allows an archive/zip Reader.Open panic via a crafted ZIP
    archive containing an invalid name or an empty filename field. (CVE-2021-41772)

  - cmd/go in Go before 1.16.14 and 1.17.x before 1.17.7 can misinterpret branch names that falsely appear to
    be version tags. This can lead to incorrect access control if an actor is supposed to be able to create
    branches but not tags. (CVE-2022-23773)

  - Go before 1.16.9 and 1.17.x before 1.17.2 has a Buffer Overflow via large arguments in a function
    invocation from a WASM module, when GOARCH=wasm GOOS=js is used. (CVE-2021-38297)

  - ImportedSymbols in debug/macho (for Open or OpenFat) in Go before 1.16.10 and 1.17.x before 1.17.3
    Accesses a Memory Location After the End of a Buffer, aka an out-of-bounds slice situation.
    (CVE-2021-41771)

  - Rat.SetString in math/big in Go before 1.16.14 and 1.17.x before 1.17.7 has an overflow that can lead to
    Uncontrolled Memory Consumption. (CVE-2022-23772)

  - Curve.IsOnCurve in crypto/elliptic in Go before 1.16.14 and 1.17.x before 1.17.7 can incorrectly return
    true in situations with a big.Int value that is not a valid field element. (CVE-2022-23806)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-1819.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:delve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:go-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-tests");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/go-toolset');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:ol8');
if ('ol8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module go-toolset:' + module_ver);

var appstreams = {
    'go-toolset:ol8': [
      {'reference':'delve-1.7.2-1.0.1.module+el8.6.0+20559+3b94dc2a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-docs-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-misc-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-race-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-src-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-tests-1.17.7-1.module+el8.6.0+20559+3b94dc2a', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:ol8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'delve / go-toolset / golang / etc');
}
