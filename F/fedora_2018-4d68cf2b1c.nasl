#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-4d68cf2b1c.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120406);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-4d68cf2b1c");

  script_name(english:"Fedora 28 : flatpak (2018-4d68cf2b1c)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"flatpak 1.0.6 release.

This release fixes an issue that lets system-wide installed
applications create setuid root files inside their app dir (somewhere
in /var/lib/flatpak/app). Setuid support is disabled inside flatpaks,
so such files are only a risk if the user runs them manually outside
flatpak.

Installing a flatpak system-wide is needs root access, so this isn't a
privilege elevation for non-root users, and allowing root to install
setuid files is something all traditional packaging systems allow.
However flatpak tries to be better than that, in order to make it
easier to trust third-party repositories.

Changes in this version :

  - The permissions of the files created by the apply_extra
    script is canonicalized and the script itself is run
    without any capabilities.

  - Better matching of existing remotes when the local and
    remote configuration differs wrt collection ids.

  - New flatpakrepo DeployCollectionID replaces
    CollectionID, doing the same thing. It is recommended to
    use this instead because older versions of flatpak has
    bugs in the support of collection ids, and this key will
    only be respected in versions where it works.

  - The X11 socket is now mounted read-only.

----

flatpak 1.0.5 release.

There was a sandbox bug in the previous version where parts of the
runtime /etc was not mounted read-only. In case the runtime was
installed as the user (not the default) this means that the app could
modify files on the runtime. Nothing in the host uses the runtime
files, so this is not a direct sandbox escape, but it is possible that
an app can confuse a different app that has higher permissions and so
gain privileges.

Detailed changes :

  - Make the /etc -> /usr/etc bind-mounts read-only.

  - Make various app-specific configuration files read-only.

  - flatpak is more picky about remote names to avoid
    problems with storing weird names in the ostree config.

  - A segfault in libflatpak handling of bundles was fixed.

  - Updated translations

  - Fixed a regression in flatpak run that caused problems
    running user-installed apps when the system installation
    was broken.

In addition to upstream changes, this update also fixes a packaging
issue and adds a missing dependency on p11-kit-server to fix accessing
host TLS certificates.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-4d68cf2b1c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flatpak package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:flatpak");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"flatpak-1.0.6-1.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flatpak");
}
