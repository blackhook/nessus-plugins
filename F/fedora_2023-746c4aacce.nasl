#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-746c4aacce
#

include('compat.inc');

if (description)
{
  script_id(170239);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2022-23521", "CVE-2022-41903");
  script_xref(name:"FEDORA", value:"2023-746c4aacce");

  script_name(english:"Fedora 36 : git (2023-746c4aacce)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-746c4aacce advisory.

  - Git is distributed revision control system. gitattributes are a mechanism to allow defining attributes for
    paths. These attributes can be defined by adding a `.gitattributes` file to the repository, which contains
    a set of file patterns and the attributes that should be set for paths matching this pattern. When parsing
    gitattributes, multiple integer overflows can occur when there is a huge number of path patterns, a huge
    number of attributes for a single pattern, or when the declared attribute names are huge. These overflows
    can be triggered via a crafted `.gitattributes` file that may be part of the commit history. Git silently
    splits lines longer than 2KB when parsing gitattributes from a file, but not when parsing them from the
    index. Consequentially, the failure mode depends on whether the file exists in the working tree, the index
    or both. This integer overflow can result in arbitrary heap reads and writes, which may result in remote
    code execution. The problem has been patched in the versions published on 2023-01-17, going back to
    v2.30.7. Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-23521)

  - Git is distributed revision control system. `git log` can display commits in an arbitrary format using its
    `--format` specifiers. This functionality is also exposed to `git archive` via the `export-subst`
    gitattribute. When processing the padding operators, there is a integer overflow in
    `pretty.c::format_and_pad_commit()` where a `size_t` is stored improperly as an `int`, and then added as
    an offset to a `memcpy()`. This overflow can be triggered directly by a user running a command which
    invokes the commit formatting machinery (e.g., `git log --format=...`). It may also be triggered
    indirectly through git archive via the export-subst mechanism, which expands format specifiers inside of
    files within the repository during a git archive. This integer overflow can result in arbitrary heap
    writes, which may result in arbitrary code execution. The problem has been patched in the versions
    published on 2023-01-17, going back to v2.30.7. Users are advised to upgrade. Users who are unable to
    upgrade should disable `git archive` in untrusted repositories. If you expose git archive via `git
    daemon`, disable it by running `git config --global daemon.uploadArch false`. (CVE-2022-41903)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-746c4aacce");
  script_set_attribute(attribute:"solution", value:
"Update the affected git package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:git");
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
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'git-2.39.1-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git');
}
