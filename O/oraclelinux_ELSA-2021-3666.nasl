#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-3666.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153765);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-3672",
    "CVE-2021-22930",
    "CVE-2021-22931",
    "CVE-2021-22939",
    "CVE-2021-22940",
    "CVE-2021-23343",
    "CVE-2021-32803",
    "CVE-2021-32804"
  );
  script_xref(name:"IAVB", value:"2021-B-0050-S");

  script_name(english:"Oracle Linux 8 : nodejs:14 (ELSA-2021-3666)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-3666 advisory.

  - c-ares: Missing input validation of host names may lead to domain hijacking (CVE-2021-3672)

  - nodejs: Use-after-free on close http2 on stream canceling (CVE-2021-22930)

  - Node.js before 16.6.0, 14.17.4, and 12.22.4 is vulnerable to Remote Code Execution, XSS, Application
    crashes due to missing input validation of host names returned by Domain Name Servers in Node.js dns
    library which can lead to output of wrong hostnames (leading to Domain Hijacking) and injection
    vulnerabilities in applications using the library. (CVE-2021-22931)

  - If the Node.js https API was used incorrectly and undefined was in passed for the rejectUnauthorized
    parameter, no error was returned and connections to servers with an expired certificate would have been
    accepted. (CVE-2021-22939)

  - Node.js before 16.6.1, 14.17.5, and 12.22.5 is vulnerable to a use after free attack where an attacker
    might be able to exploit the memory corruption, to change process behavior. (CVE-2021-22940)

  - The npm package tar (aka node-tar) before versions 6.1.2, 5.0.7, 4.4.15, and 3.2.3 has an arbitrary File
    Creation/Overwrite vulnerability via insufficient symlink protection. `node-tar` aims to guarantee that
    any file whose location would be modified by a symbolic link is not extracted. This is, in part, achieved
    by ensuring that extracted directories are not symlinks. Additionally, in order to prevent unnecessary
    `stat` calls to determine whether a given path is a directory, paths are cached when directories are
    created. This logic was insufficient when extracting tar files that contained both a directory and a
    symlink with the same name as the directory. This order of operations resulted in the directory being
    created and added to the `node-tar` directory cache. When a directory is present in the directory cache,
    subsequent calls to mkdir for that directory are skipped. However, this is also where `node-tar` checks
    for symlinks occur. By first creating a directory, and then replacing that directory with a symlink, it
    was thus possible to bypass `node-tar` symlink checks on directories, essentially allowing an untrusted
    tar file to symlink into an arbitrary location and subsequently extracting arbitrary files into that
    location, thus allowing arbitrary file creation and overwrite. This issue was addressed in releases 3.2.3,
    4.4.15, 5.0.7 and 6.1.2. (CVE-2021-32803)

  - The npm package tar (aka node-tar) before versions 6.1.1, 5.0.6, 4.4.14, and 3.3.2 has a arbitrary File
    Creation/Overwrite vulnerability due to insufficient absolute path sanitization. node-tar aims to prevent
    extraction of absolute file paths by turning absolute paths into relative paths when the `preservePaths`
    flag is not set to `true`. This is achieved by stripping the absolute path root from any absolute file
    paths contained in a tar file. For example `/home/user/.bashrc` would turn into `home/user/.bashrc`. This
    logic was insufficient when file paths contained repeated path roots such as `////home/user/.bashrc`.
    `node-tar` would only strip a single path root from such paths. When given an absolute file path with
    repeating path roots, the resulting path (e.g. `///home/user/.bashrc`) would still resolve to an absolute
    path, thus allowing arbitrary file creation and overwrite. This issue was addressed in releases 3.2.2,
    4.4.14, 5.0.6 and 6.1.1. Users may work around this vulnerability without upgrading by creating a custom
    `onentry` method which sanitizes the `entry.path` or a `filter` method which removes entries with absolute
    paths. See referenced GitHub Advisory for details. Be aware of CVE-2021-32803 which fixes a similar bug in
    later versions of tar. (CVE-2021-32804)

  - All versions of package path-parse are vulnerable to Regular Expression Denial of Service (ReDoS) via
    splitDeviceRe, splitTailRe, and splitPathRe regular expressions. ReDoS exhibits polynomial worst-case time
    complexity. (CVE-2021-23343)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-3666.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:npm");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
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

var module_ver = get_kb_item('Host/RedHat/appstream/nodejs');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:14');
if ('14' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module nodejs:' + module_ver);

var appstreams = {
    'nodejs:14': [
      {'reference':'nodejs-14.17.5-1.module+el8.4.0+20313+f90c2973', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-14.17.5-1.module+el8.4.0+20313+f90c2973', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-14.17.5-1.module+el8.4.0+20313+f90c2973', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-14.17.5-1.module+el8.4.0+20313+f90c2973', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-docs-14.17.5-1.module+el8.4.0+20313+f90c2973', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-14.17.5-1.module+el8.4.0+20313+f90c2973', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-14.17.5-1.module+el8.4.0+20313+f90c2973', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-nodemon-2.0.3-1.module+el8.3.0+7818+6cd30d85', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nodejs-packaging-23-3.module+el8.3.0+7818+6cd30d85', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'npm-6.14.14-1.14.17.5.1.module+el8.4.0+20313+f90c2973', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-6.14.14-1.14.17.5.1.module+el8.4.0+20313+f90c2973', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:14');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-devel / nodejs-docs / etc');
}
