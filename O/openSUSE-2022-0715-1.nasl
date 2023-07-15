#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0715-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158624);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/05");

  script_cve_id(
    "CVE-2021-3807",
    "CVE-2021-3918",
    "CVE-2021-23343",
    "CVE-2021-32803",
    "CVE-2021-32804"
  );

  script_name(english:"openSUSE 15 Security Update : nodejs14 (openSUSE-SU-2022:0715-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0715-1 advisory.

  - All versions of package path-parse are vulnerable to Regular Expression Denial of Service (ReDoS) via
    splitDeviceRe, splitTailRe, and splitPathRe regular expressions. ReDoS exhibits polynomial worst-case time
    complexity. (CVE-2021-23343)

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

  - ansi-regex is vulnerable to Inefficient Regular Expression Complexity (CVE-2021-3807)

  - json-schema is vulnerable to Improperly Controlled Modification of Object Prototype Attributes ('Prototype
    Pollution') (CVE-2021-3918)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192696");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VAM6LOV2R24IH5PPUWLXB64PALLMBOTU/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a34fa804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3918");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs14, nodejs14-devel and / or npm14 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3918");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs14-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'nodejs14-14.19.0-15.27.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs14-devel-14.19.0-15.27.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm14-14.19.0-15.27.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs14 / nodejs14-devel / npm14');
}
