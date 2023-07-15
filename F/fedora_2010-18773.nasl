#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-18773.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51130);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2010-0179", "CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777");
  script_xref(name:"FEDORA", value:"2010-18773");

  script_name(english:"Fedora 14 : firefox-3.6.13-1.fc14 / galeon-2.0.7-36.fc14.1 / gnome-python2-extras-2.25.3-26.fc14.1 / etc (2010-18773)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.6.13, fixing multiple
security issues detailed in the upstream advisories :

http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#f
irefox3.6.13

Update also includes all packages depending on gecko-libs rebuilt
against new version of Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#firefox3.6.13
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c81664e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660439"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-December/052029.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c525a34"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-December/052030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0355bd09"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-December/052031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78d33b3f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-December/052032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ac95e28"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-December/052033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2324f8b5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-December/052034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66cc8e92"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-December/052035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbb73d46"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC14", reference:"firefox-3.6.13-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"galeon-2.0.7-36.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-python2-extras-2.25.3-26.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-web-photo-0.9-16.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"mozvoikko-1.0-17.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"perl-Gtk2-MozEmbed-0.08-6.fc14.22")) flag++;
if (rpm_check(release:"FC14", reference:"xulrunner-1.9.2.13-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / galeon / gnome-python2-extras / gnome-web-photo / etc");
}
