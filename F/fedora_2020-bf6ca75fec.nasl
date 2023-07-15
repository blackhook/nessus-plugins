#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-bf6ca75fec.
#

include("compat.inc");

if (description)
{
  script_id(134334);
  script_version("1.1");
  script_cvs_date("Date: 2020/03/09");

  script_xref(name:"FEDORA", value:"2020-bf6ca75fec");

  script_name(english:"Fedora 31 : seamonkey (2020-bf6ca75fec)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upgrade to 2.53.1

SeaMonkey-2.53.1, being initially based on the Firefox-56 and
Thunderbird-56 code, incorporates now a lot of backported features and
security fixes from the newer Firefox/Thunderbird versions up to 75.
That way it tries to be a modern browser, preserving the same time the
familiar user interface and the ability to use traditional extensions
and addons.

This version makes changes to your profile that can't be reverted in
case you want to go back to a previous version of SeaMonkey. You MUST
absolutely do a full backup of your profile (~/.mozilla/seamonkey/
dir) BEFORE trying to run new version.

SeaMonkey now uses GTK3 library for GUI interface. If you experienced
some size issues, go to 'about:config' and try to set
'layout.css.devPixelsPerPx' preference to '1' (or any other preferred
value). You can also use gtk3's environment variables GDK_SCALE and/or
GDK_DPI_SCALE (useful for HiDPI displays). Since Classic theme uses
system desktop theme, it might behaves incorrectly when the underlying
theme (still) does not support gtk3.

Full theme add-ons may need changes because of user interface and
internal changes. If you find any problem with themes, contact the
theme author. Before reporting a problem with the user interface,
please make sure to recreate it with either the Classic or Modern
theme.

This version now includes 'Lightning' calendar. It becomes a standard
part of Thunderbird/SeaMonkey, being just technically organized as an
extension. This version returns providing of Chatzilla and DOM
inspector extensions, just as it always was before.

It is likely you need to update your third-party extensions to newer
versions. Poorly designed or incompatible extensions can cause
unpredictable problems. If you encounter some strange issues, try
'seamonkey -safe-mode' from command line.

Unfortunately, it is now impossible to continue support of npapi
plugins. Thus, java applets no more work :( . All modern browsers have
dropped such support years ago, and even plugin owners recommend to
not use it anymore. Search 'browsers with java support' if you still
need it. Sorry for that. Flash is still supported, at least until its
EOL at the end of 2020.

Since 2.53.1, 32-bit version (i686 arch) does not provided, because no
more supported.

The old format of keys and certificates storage in the user profiles
still preserved in Fedora. DO NOT TOUCH key3.db and cert8.db files (as
it might be recommended in the upstream release notes) -- they still
works as expected.

Please, read upstream release notes for more info
https://www.seamonkey-project.org/releases/seamonkey2.53.1/

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-bf6ca75fec"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.seamonkey-project.org/releases/seamonkey2.53.1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"seamonkey-2.53.1-2.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}
