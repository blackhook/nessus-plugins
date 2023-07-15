#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-e31c3e4b6c
#

include('compat.inc');

if (description)
{
  script_id(171908);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/02");
  script_xref(name:"FEDORA", value:"2023-e31c3e4b6c");

  script_name(english:"Fedora 37 : bluedevil / breeze-gtk / flatpak-kcm / grub2-breeze-theme / etc (2023-e31c3e4b6c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2023-e31c3e4b6c advisory.

  - Plasma 5.27.1  ----  Add patch to disable global shortcuts at login for the SDDM Plasma Wayland
    configuration (#2171332)     (FEDORA-2023-e31c3e4b6c)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-e31c3e4b6c");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bluedevil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:breeze-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:flatpak-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:grub2-breeze-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kactivitymanagerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-cli-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-gtk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdecoration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdeplasma-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:khotkeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kinfocenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kpipewire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kscreen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kscreenlocker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksshaskpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ksystemstats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kwayland-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kwrited");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:layer-shell-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libkscreen-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libksysguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:oxygen-sounds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pam-kwallet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-browser-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-discover");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-disks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-drkonqi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-firewall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-milou");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-nano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-systemmonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-systemsettings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-thunderbolt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-vault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-welcome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-workspace-wallpapers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plymouth-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plymouth-theme-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:polkit-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:powerdevil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qqc2-breeze-style");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sddm-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xdg-desktop-portal-kde");
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
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'bluedevil-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'breeze-gtk-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'flatpak-kcm-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-breeze-theme-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kactivitymanagerd-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-cli-tools-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-gtk-config-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kdecoration-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kdeplasma-addons-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kgamma-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'khotkeys-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kinfocenter-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kmenuedit-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kpipewire-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kscreen-5.27.1.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'kscreenlocker-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksshaskpass-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksystemstats-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwayland-integration-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-5.27.1-2.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwrited-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'layer-shell-qt-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkscreen-qt5-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libksysguard-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oxygen-sounds-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pam-kwallet-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-breeze-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-browser-integration-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-desktop-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-discover-5.27.1-2.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-disks-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-drkonqi-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-firewall-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-integration-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-milou-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-mobile-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-nano-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-nm-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-oxygen-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-pa-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-sdk-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-systemmonitor-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-systemsettings-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-thunderbolt-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-vault-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-welcome-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-workspace-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-workspace-wallpapers-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-kcm-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-breeze-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-kde-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'powerdevil-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qqc2-breeze-style-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sddm-kcm-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xdg-desktop-portal-kde-5.27.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bluedevil / breeze-gtk / flatpak-kcm / grub2-breeze-theme / etc');
}
