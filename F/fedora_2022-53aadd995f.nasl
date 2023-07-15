#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-53aadd995f
#

include('compat.inc');

if (description)
{
  script_id(169117);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/22");

  script_cve_id("CVE-2022-39253", "CVE-2022-39260");
  script_xref(name:"FEDORA", value:"2022-53aadd995f");

  script_name(english:"Fedora 35 : git (2022-53aadd995f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 35 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-53aadd995f advisory.

  - Git is an open source, scalable, distributed revision control system. Versions prior to 2.30.6, 2.31.5,
    2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 are subject to exposure of sensitive information to a
    malicious actor. When performing a local clone (where the source and target of the clone are on the same
    volume), Git copies the contents of the source's `$GIT_DIR/objects` directory into the destination by
    either creating hardlinks to the source contents, or copying them (if hardlinks are disabled via `--no-
    hardlinks`). A malicious actor could convince a victim to clone a repository with a symbolic link pointing
    at sensitive information on the victim's machine. This can be done either by having the victim clone a
    malicious repository on the same machine, or having them clone a malicious repository embedded as a bare
    repository via a submodule from any source, provided they clone with the `--recurse-submodules` option.
    Git does not create symbolic links in the `$GIT_DIR/objects` directory. The problem has been patched in
    the versions published on 2022-10-18, and backported to v2.30.x. Potential workarounds: Avoid cloning
    untrusted repositories using the `--local` optimization when on a shared machine, either by passing the
    `--no-local` option to `git clone` or cloning from a URL that uses the `file://` scheme. Alternatively,
    avoid cloning repositories from untrusted sources with `--recurse-submodules` or run `git config --global
    protocol.file.allow user`. (CVE-2022-39253)

  - Git is an open source, scalable, distributed revision control system. `git shell` is a restricted login
    shell that can be used to implement Git's push/pull functionality via SSH. In versions prior to 2.30.6,
    2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4, the function that splits the command arguments
    into an array improperly uses an `int` to represent the number of entries in the array, allowing a
    malicious actor to intentionally overflow the return value, leading to arbitrary heap writes. Because the
    resulting array is then passed to `execv()`, it is possible to leverage this attack to gain remote code
    execution on a victim machine. Note that a victim must first allow access to `git shell` as a login shell
    in order to be vulnerable to this attack. This problem is patched in versions 2.30.6, 2.31.5, 2.32.4,
    2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 and users are advised to upgrade to the latest version.
    Disabling `git shell` access via remote logins is a viable short-term workaround. (CVE-2022-39260)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-53aadd995f");
  script_set_attribute(attribute:"solution", value:
"Update the affected git package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39260");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:git");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^35([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 35', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'git-2.38.1-1.fc35', 'release':'FC35', 'rpm_spec_vers_cmp':TRUE}
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
