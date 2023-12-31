#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-1606.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58079);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2012-1606");

  script_name(english:"Fedora 15 : firefox-10.0.1-1.fc15 / thunderbird-10.0.1-1.fc15 / xulrunner-10.0.1-1.fc15 (2012-1606)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"For list of changes see official changelog:
http://www.mozilla.org/en-US/firefox/10.0.1/releasenotes/
http://www.mozilla.org/en-US/thunderbird/10.0.1/releasenotes/

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/en-US/firefox/10.0.1/releasenotes/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d31c75dc"
  );
  # http://www.mozilla.org/en-US/thunderbird/10.0.1/releasenotes/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a8695fd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073544.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c1d570d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073545.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fc0c6e0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36a33e35"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox, thunderbird and / or xulrunner packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC15", reference:"firefox-10.0.1-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"thunderbird-10.0.1-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"xulrunner-10.0.1-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / thunderbird / xulrunner");
}
