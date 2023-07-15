#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-ac2a21ff07.
#

include("compat.inc");

if (description)
{
  script_id(124529);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/23 11:21:11");

  script_xref(name:"FEDORA", value:"2019-ac2a21ff07");

  script_name(english:"Fedora 30 : 1:gnome-bluetooth / at-spi2-core / atomix / bijiben / containers / etc (2019-ac2a21ff07)");
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
pending (in those cases, those updates have been edited instead). This
includes gnome-initial-setup, which was affected by this problem,
resulting in a [release-blocking
bug](https://bugzilla.redhat.com/show_bug.cgi?id=1699099) that
prevented it running correctly with SELinux in enforcing mode.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-ac2a21ff07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1699099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/mesonbuild/meson/issues/5268"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:gnome-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:at-spi2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:atomix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bijiben");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:containers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dav1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dbus-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dsymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:egl-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:elementary-camera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:elementary-code");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:elementary-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ephemeral");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:file-roller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fondo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fwupd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gamemode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:geocode-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gir-to-d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glib-networking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-books");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-boxes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-calculator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-characters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-desktop3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-disk-utility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-initial-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-maps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-music");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-shell-extension-gsconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-system-monitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-weather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gobject-introspection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:group-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libdazzle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libdparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libmodulemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libnotify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libplacebo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libxmlb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mate-user-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:meson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mpris-scrobbler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:msgpack-d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:polari");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:reportd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:shotwell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:signon-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:simple-scan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:stdx-allocator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:switchboard-plug-display");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:switchboard-plug-pantheon-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:toolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wingpanel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:zchunk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/02");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"gnome-bluetooth-3.32.1-2.fc30", epoch:"1")) flag++;
if (rpm_check(release:"FC30", reference:"at-spi2-core-2.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"atomix-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"bijiben-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"containers-0.8.0-8.alpha.9.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"dav1d-0.2.1-3.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"dbus-broker-20-3.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"dsymbol-20181014gitec28618-8.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"egl-wayland-1.1.2-3.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"elementary-camera-1.0.4-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"elementary-code-3.1.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"elementary-terminal-5.3.4-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"eog-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"ephemeral-5.0.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"file-roller-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"fondo-1.2.2-4.20190324git71d97ee.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"fuse-2.9.9-3.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"fwupd-1.2.7-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gamemode-1.2-4.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"geocode-glib-3.26.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gir-to-d-0.18.0-4.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"glib-networking-2.60.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"glib2-2.60.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-books-3.32.0-3.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-boxes-3.32.0.2-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-builder-3.32.1-4.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-calculator-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-characters-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-control-center-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-desktop3-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-disk-utility-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-initial-setup-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-maps-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-music-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-shell-extension-gsconnect-21-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-software-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-system-monitor-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gnome-weather-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gobject-introspection-1.60.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"group-service-1.1.0-5.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"gvfs-1.40.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"libdazzle-3.32.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"libdparse-0.9.9-7.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"libinput-1.13.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"libmodulemd-2.2.3-3.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"libnotify-0.7.8-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"libplacebo-1.18.0-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"libsoup-2.66.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"libxmlb-0.1.8-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"mate-user-admin-1.4.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"mesa-19.0.2-3.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"meson-0.50.0-4.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"mpris-scrobbler-0.3.2-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"msgpack-d-1.0.0-0.6.beta.7.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"polari-3.32.0-3.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"reportd-0.6.6-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"shotwell-0.31.0-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"signon-glib-2.1-4.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"simple-scan-3.32.2-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"stdx-allocator-2.77.2-7.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"switchboard-plug-display-2.1.7-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"switchboard-plug-pantheon-shell-2.8.1-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"systemd-241-7.gita2eaa1c.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"toolbox-0.0.8-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"wingpanel-2.2.3-2.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"zchunk-1.1.1-3.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:gnome-bluetooth / at-spi2-core / atomix / bijiben / containers / etc");
}
