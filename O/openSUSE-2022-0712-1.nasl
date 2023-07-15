#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0712-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158641);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/05");

  script_cve_id("CVE-2021-43860", "CVE-2022-21682");

  script_name(english:"openSUSE 15 Security Update : flatpak (openSUSE-SU-2022:0712-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0712-1 advisory.

  - Flatpak is a Linux application sandboxing and distribution framework. Prior to versions 1.12.3 and 1.10.6,
    Flatpak doesn't properly validate that the permissions displayed to the user for an app at install time
    match the actual permissions granted to the app at runtime, in the case that there's a null byte in the
    metadata file of an app. Therefore apps can grant themselves permissions without the consent of the user.
    Flatpak shows permissions to the user during install by reading them from the xa.metadata key in the
    commit metadata. This cannot contain a null terminator, because it is an untrusted GVariant. Flatpak
    compares these permissions to the *actual* metadata, from the metadata file to ensure it wasn't lied to.
    However, the actual metadata contents are loaded in several places where they are read as simple C-style
    strings. That means that, if the metadata file includes a null terminator, only the content of the file
    from *before* the terminator gets compared to xa.metadata. Thus, any permissions that appear in the
    metadata file after a null terminator are applied at runtime but not shown to the user. So maliciously
    crafted apps can give themselves hidden permissions. Users who have Flatpaks installed from untrusted
    sources are at risk in case the Flatpak has a maliciously crafted metadata file, either initially or in an
    update. This issue is patched in versions 1.12.3 and 1.10.6. As a workaround, users can manually check the
    permissions of installed apps by checking the metadata file or the xa.metadata key on the commit metadata.
    (CVE-2021-43860)

  - Flatpak is a Linux application sandboxing and distribution framework. A path traversal vulnerability
    affects versions of Flatpak prior to 1.12.3 and 1.10.6. flatpak-builder applies `finish-args` last in the
    build. At this point the build directory will have the full access that is specified in the manifest, so
    running `flatpak build` against it will gain those permissions. Normally this will not be done, so this is
    not problem. However, if `--mirror-screenshots-url` is specified, then flatpak-builder will launch
    `flatpak build --nofilesystem=host appstream-utils mirror-screenshots` after finalization, which can lead
    to issues even with the `--nofilesystem=host` protection. In normal use, the only issue is that these
    empty directories can be created wherever the user has write permissions. However, a malicious application
    could replace the `appstream-util` binary and potentially do something more hostile. This has been
    resolved in Flatpak 1.12.3 and 1.10.6 by changing the behaviour of `--nofilesystem=home` and
    `--nofilesystem=host`. (CVE-2022-21682)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194611");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T4OG73MX3JPZBHYMUXUULPTVL7ZOOTZ5/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15f22acc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21682");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flatpak-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libflatpak0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:system-user-flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Flatpak-1_0");
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
    {'reference':'flatpak-1.10.7-4.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-devel-1.10.7-4.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-zsh-completion-1.10.7-4.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libflatpak0-1.10.7-4.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'system-user-flatpak-1.10.7-4.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'typelib-1_0-Flatpak-1_0-1.10.7-4.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'flatpak / flatpak-devel / flatpak-zsh-completion / libflatpak0 / etc');
}
