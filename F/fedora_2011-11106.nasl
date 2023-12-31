#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-11106.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55893);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2011-11106");

  script_name(english:"Fedora 15 : firefox-6.0-1.fc15 / gnome-python2-extras-2.25.3-33.fc15 / mozvoikko-1.9.0-6.fc15 / etc (2011-11106)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 6.0, fixing multiple security
issues detailed in the upstream advisory :

  -
    http://www.mozilla.org/security/announce/2011/mfsa2011-2
    9.html

This update also includes all packages depending on gecko-libs rebuilt
against the new version of Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-29.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-29/"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e962a2e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7fa553d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de2efbe9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063900.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbcbba7b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063901.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d20bbd74"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"firefox-6.0-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"gnome-python2-extras-2.25.3-33.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"mozvoikko-1.9.0-6.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"perl-Gtk2-MozEmbed-0.09-1.fc15.2")) flag++;
if (rpm_check(release:"FC15", reference:"xulrunner-6.0-2.fc15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / gnome-python2-extras / mozvoikko / perl-Gtk2-MozEmbed / etc");
}
