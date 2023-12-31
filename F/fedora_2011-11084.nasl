#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-11084.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55953);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(49213, 49214, 49216, 49217, 49218, 49219, 49223);
  script_xref(name:"FEDORA", value:"2011-11084");

  script_name(english:"Fedora 14 : firefox-3.6.20-1.fc14 / galeon-2.0.7-42.fc14.1 / gnome-python2-extras-2.25.3-32.fc14.1 / etc (2011-11084)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.6.20 and Thunderbird version
3.1.12, fixing multiple security issues detailed in the upstream
advisories :

  -
    http://www.mozilla.org/security/announce/2011/mfsa2011-3
    0.html

    -
      http://www.mozilla.org/security/announce/2011/mfsa2011
      -32.html

This update also includes all packages depending on gecko-libs rebuilt
against the new version of Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-30.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-30/"
  );
  # http://www.mozilla.org/security/announce/2011/mfsa2011-32.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-32/"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064381.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2f4309a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064382.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd1eebf2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064383.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4828eb2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064384.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bbddffc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064385.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e487005"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064386.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fdfb173"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064387.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e76357e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064388.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50a2fd80"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/064390.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e15ab3d2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/23");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"firefox-3.6.20-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"galeon-2.0.7-42.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-python2-extras-2.25.3-32.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-web-photo-0.9-22.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"mozvoikko-1.0-23.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"perl-Gtk2-MozEmbed-0.08-6.fc14.28")) flag++;
if (rpm_check(release:"FC14", reference:"thunderbird-3.1.12-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"thunderbird-lightning-1.0-0.42.b3pre.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"xulrunner-1.9.2.20-1.fc14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / galeon / gnome-python2-extras / gnome-web-photo / etc");
}
