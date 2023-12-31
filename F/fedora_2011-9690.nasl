#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-9690.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55843);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-2720");
  script_bugtraq_id(48884);
  script_xref(name:"FEDORA", value:"2011-9690");

  script_name(english:"Fedora 14 : glpi-0.78.5-2.svn14966.fc14 / glpi-data-injection-2.0.2-1.fc14 / etc (2011-9690)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New major version of GLPI and plugins.

For more information, see announcement on
http://www.glpi-project.org/spip.php?lang=en

This update also include a security fix.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.glpi-project.org/spip.php?lang=en
  script_set_attribute(
    attribute:"see_also",
    value:"http://glpi-project.org/spip.php?lang=en"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=726186"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063677.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a14fd686"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063678.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bfcfa22"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063679.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff6d6053"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28182f7f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063695.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e05803c9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063696.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9abaeb23"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e883e6c2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-August/063698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d776e2f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi-data-injection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi-mass-ocs-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi-pdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");
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
if (rpm_check(release:"FC14", reference:"glpi-0.78.5-2.svn14966.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"glpi-data-injection-2.0.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"glpi-mass-ocs-import-1.4.2-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"glpi-pdf-0.7.2-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glpi / glpi-data-injection / glpi-mass-ocs-import / glpi-pdf");
}
