#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-16351.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62610);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2012-16351");

  script_name(english:"Fedora 16 : java-1.6.0-openjdk-1.6.0.0-68.1.11.5.fc16 / java-1.7.0-openjdk-1.7.0.9-2.3.3.fc16 (2012-16351)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes numerous security issues in the OpenJDK packages
that are fixed as part of the October 2012 Java CPU.

Fixed bugs: 856124, 865346, 865348, 865350, 865352, 865354, 865357,
865359, 865363, 865365, 865370, 865428, 865471, 865434, 865511,
865514, 865519, 865531, 865541, 865568

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-October/090195.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f21b325"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-October/090196.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05725bfc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected java-1.6.0-openjdk and / or java-1.7.0-openjdk
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"java-1.6.0-openjdk-1.6.0.0-68.1.11.5.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"java-1.7.0-openjdk-1.7.0.9-2.3.3.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.7.0-openjdk");
}
