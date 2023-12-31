##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-17956.
##

include('compat.inc');

if (description)
{
  script_id(163040);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-24675",
    "CVE-2022-27536",
    "CVE-2022-28327",
    "CVE-2022-29526",
    "CVE-2022-29804",
    "CVE-2022-30580",
    "CVE-2022-30629",
    "CVE-2022-30634"
  );

  script_name(english:"Oracle Linux 8 : go-toolset:ol8addon (ELSA-2022-17956)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-17956 advisory.

  - encoding/pem in Go before 1.17.9 and 1.18.x before 1.18.1 has a Decode stack overflow via a large amount
    of PEM data. (CVE-2022-24675)

  - The generic P-256 feature in crypto/elliptic in Go before 1.17.9 and 1.18.x before 1.18.1 allows a panic
    via long scalar input. (CVE-2022-28327)

  - Go before 1.17.10 and 1.18.x before 1.18.2 has Incorrect Privilege Assignment. When called with a non-zero
    flags parameter, the Faccessat function could incorrectly report that a file is accessible.
    (CVE-2022-29526)

  - Certificate.Verify in crypto/x509 in Go 1.18.x before 1.18.1 can be caused to panic on macOS when
    presented with certain malformed certificates. This allows a remote TLS server to cause a TLS client to
    panic. (CVE-2022-27536)

  - The Go project reports: crypto/rand: rand.Read hangs with extremely large buffers On Windows, rand.Read
    will hang indefinitely if passed a             buffer larger than 1 << 32 - 1 bytes. crypto/tls: session
    tickets lack random ticket_age_add Session tickets generated by crypto/tls did not contain             a
    randomly generated ticket_age_add. This allows an             attacker that can observe TLS handshakes to
    correlate             successive connections by comparing ticket ages during             session
    resumption. os/exec: empty Cmd.Path can result in running unintended             binary on Windows If, on
    Windows, Cmd.Run, cmd.Start, cmd.Output, or             cmd.CombinedOutput are executed when Cmd.Path is
    unset             and, in the working directory, there are binaries named             either ..com or
    ..exe, they will be executed. path/filepath: Clean(`.\c:`) returns `c:` on Windows On Windows, the
    filepath.Clean function could convert an             invalid path to a valid, absolute path. For example,
    Clean(`.\c:`) returned `c:`. (CVE-2022-29804, CVE-2022-30580, CVE-2022-30634)

  - Automatic update for grafana-8.5.6-1.fc37.  ##### **Changelog**  ``` * Wed Jun 29 2022 Andreas Gerstmayr
    <agerstmayr@redhat.com> 8.5.6-1 - update to 8.5.6 tagged upstream community sources, see CHANGELOG -
    updated license to AGPLv3 - place commented sample config file in /etc/grafana/grafana.ini - enable Go
    modules in build process - adapt Node.js bundling to yarn v3 and Zero Install feature * Sun Jun 19 2022
    Robert-Andr Mauchin <zebob.m@gmail.com> - 7.5.15-3 - Rebuilt for CVE-2022-1996, CVE-2022-24675,
    CVE-2022-28327, CVE-2022-27191,   CVE-2022-29526, CVE-2022-30629  ``` (CVE-2022-30629)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-17956.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29526");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30580");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:delve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:go-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:ol8addon');
if ('ol8addon' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module go-toolset:' + module_ver);

var appstreams = {
    'go-toolset:ol8addon': [
      {'reference':'delve-1.8.3-1.0.1.module+el8.6.0+20704+139a7dad', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'delve-1.8.3-1.0.1.module+el8.6.0+20704+139a7dad', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.18.3-1.module+el8.6.0+20704+139a7dad', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'go-toolset-1.18.3-1.module+el8.6.0+20704+139a7dad', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-bin-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-docs-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-misc-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-race-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-src-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'golang-tests-1.18.3-1.0.1.module+el8.6.0+20704+139a7dad', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module go-toolset:ol8addon');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'delve / go-toolset / golang / etc');
}
