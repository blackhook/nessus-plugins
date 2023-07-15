#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3284-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165227);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2021-21261", "CVE-2021-41133", "CVE-2021-43860");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3284-1");

  script_name(english:"SUSE SLES15 Security Update : flatpak (SUSE-SU-2022:3284-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3284-1 advisory.

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. A bug
    was discovered in the `flatpak-portal` service that can allow sandboxed applications to execute arbitrary
    code on the host system (a sandbox escape). This sandbox-escape bug is present in versions from 0.11.4 and
    before fixed versions 1.8.5 and 1.10.0. The Flatpak portal D-Bus service (`flatpak-portal`, also known by
    its D-Bus service name `org.freedesktop.portal.Flatpak`) allows apps in a Flatpak sandbox to launch their
    own subprocesses in a new sandbox instance, either with the same security settings as the caller or with
    more restrictive security settings. For example, this is used in Flatpak-packaged web browsers such as
    Chromium to launch subprocesses that will process untrusted web content, and give those subprocesses a
    more restrictive sandbox than the browser itself. In vulnerable versions, the Flatpak portal service
    passes caller-specified environment variables to non-sandboxed processes on the host system, and in
    particular to the `flatpak run` command that is used to launch the new sandbox instance. A malicious or
    compromised Flatpak app could set environment variables that are trusted by the `flatpak run` command, and
    use them to execute arbitrary code that is not in a sandbox. As a workaround, this vulnerability can be
    mitigated by preventing the `flatpak-portal` service from starting, but that mitigation will prevent many
    Flatpak apps from working correctly. This is fixed in versions 1.8.5 and 1.10.0. (CVE-2021-21261)

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. In
    versions prior to 1.10.4 and 1.12.0, Flatpak apps with direct access to AF_UNIX sockets such as those used
    by Wayland, Pipewire or pipewire-pulse can trick portals and other host-OS services into treating the
    Flatpak app as though it was an ordinary, non-sandboxed host-OS process. They can do this by manipulating
    the VFS using recent mount-related syscalls that are not blocked by Flatpak's denylist seccomp filter, in
    order to substitute a crafted `/.flatpak-info` or make that file disappear entirely. Flatpak apps that act
    as clients for AF_UNIX sockets such as those used by Wayland, Pipewire or pipewire-pulse can escalate the
    privileges that the corresponding services will believe the Flatpak app has. Note that protocols that
    operate entirely over the D-Bus session bus (user bus), system bus or accessibility bus are not affected
    by this. This is due to the use of a proxy process `xdg-dbus-proxy`, whose VFS cannot be manipulated by
    the Flatpak app, when interacting with these buses. Patches exist for versions 1.10.4 and 1.12.0, and as
    of time of publication, a patch for version 1.8.2 is being planned. There are no workarounds aside from
    upgrading to a patched version. (CVE-2021-41133)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194610");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012249.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24d11631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43860");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21261");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libflatpak0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Flatpak-1_0");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'flatpak-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'flatpak-devel-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'flatpak-zsh-completion-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'libflatpak0-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'flatpak-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'flatpak-devel-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'flatpak-zsh-completion-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'libflatpak0-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'flatpak-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'flatpak-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'flatpak-devel-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'flatpak-devel-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'flatpak-zsh-completion-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'flatpak-zsh-completion-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libflatpak0-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libflatpak0-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.2.3-150100.4.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'flatpak-1.2.3-150100.4.8.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'flatpak-devel-1.2.3-150100.4.8.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'flatpak-zsh-completion-1.2.3-150100.4.8.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libflatpak0-1.2.3-150100.4.8.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'typelib-1_0-Flatpak-1_0-1.2.3-150100.4.8.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'flatpak / flatpak-devel / flatpak-zsh-completion / libflatpak0 / etc');
}
