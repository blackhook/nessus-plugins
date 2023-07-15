#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-27e7b92407.
#

include("compat.inc");

if (description)
{
  script_id(124207);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/23 11:21:10");

  script_xref(name:"FEDORA", value:"2019-27e7b92407");

  script_name(english:"Fedora 29 : egl-wayland / elementary-camera / elementary-code / etc (2019-27e7b92407)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a
[bug](https://github.com/mesonbuild/meson/issues/5268) in the Meson
build system which caused binaries and libraries to incorrectly be
marking as requiring an executable stack. This makes them more
vulnerable to security issues, and also can result in errors caused by
SELinux denials.

This update also provides rebuilds of all the packages that were built
with the buggy Meson, excepting packages for updates were already
pending (in those cases, those updates have been edited instead).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-27e7b92407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/mesonbuild/meson/issues/5268"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:egl-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:elementary-camera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:elementary-code");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:elementary-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ephemeral");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fondo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:geocode-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-characters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-shell-extension-gsconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:group-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libmodulemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxmlb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mate-user-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:meson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mpris-scrobbler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:reportd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:switchboard-plug-display");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:switchboard-plug-pantheon-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wingpanel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"egl-wayland-1.1.2-3.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"elementary-camera-1.0.4-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"elementary-code-3.1.1-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"elementary-terminal-5.3.4-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"ephemeral-5.0.1-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"fondo-1.2.2-4.20190324git71d97ee.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"fuse-2.9.9-3.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"geocode-glib-3.26.1-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"gnome-characters-3.30.0-3.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"gnome-shell-extension-gsconnect-21-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"group-service-1.1.0-5.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"libmodulemd-2.2.3-3.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"libxmlb-0.1.8-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mate-user-admin-1.4.1-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mesa-18.3.6-3.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"meson-0.50.0-4.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"mpris-scrobbler-0.3.2-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"reportd-0.6.6-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"switchboard-plug-display-2.1.7-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"switchboard-plug-pantheon-shell-2.8.1-2.fc29")) flag++;
if (rpm_check(release:"FC29", reference:"wingpanel-2.2.3-2.fc29")) flag++;


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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "egl-wayland / elementary-camera / elementary-code / etc");
}
