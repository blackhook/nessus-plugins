#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-8073.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34224);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2008-8073");

  script_name(english:"Fedora 9 : fedora-package-config-apt-9-3.transitional / etc (2008-8073)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update sets up the new update locations for smart and apt
('newkey').

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462037"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014330.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0128f561"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014331.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6a9cbd4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected fedora-package-config-apt and / or
fedora-package-config-smart packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fedora-package-config-apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fedora-package-config-smart");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"fedora-package-config-apt-9-3.transitional")) flag++;
if (rpm_check(release:"FC9", reference:"fedora-package-config-smart-9-13.0.2.transitional")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fedora-package-config-apt / fedora-package-config-smart");
}
