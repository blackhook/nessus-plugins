#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-15200.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86034);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2015-15200");

  script_name(english:"Fedora 23 : php-doctrine-cache-1.4.2-1.fc23 (2015-15200)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2015-5723
http://www.doctrine-project.org/2015/08/31/security_misconfigurat
ion_vulnerability_in_various_doctrine_projects.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.doctrine-project.org/2015/08/31/security_misconfigurat
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.doctrine-project.org/2015/08/31/security_misconfigurat"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1258670"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-September/166577.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17a41e90"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-doctrine-cache package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-doctrine-cache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"php-doctrine-cache-1.4.2-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-doctrine-cache");
}
