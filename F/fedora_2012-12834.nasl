#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-12834.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62139);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2012-12834");

  script_name(english:"Fedora 18 : firefox-15.0-1.fc18 / thunderbird-15.0-1.fc18 / thunderbird-lightning-1.7-2.fc18 / etc (2012-12834)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 10.0.7

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/086879.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c55d60d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/086880.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2c6b59e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/086881.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b6e085a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/086882.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?275a72cc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"firefox-15.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"thunderbird-15.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"thunderbird-lightning-1.7-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"xulrunner-15.0-2.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / thunderbird / thunderbird-lightning / xulrunner");
}
