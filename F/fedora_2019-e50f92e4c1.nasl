#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-e50f92e4c1.
#

include("compat.inc");

if (description)
{
  script_id(124550);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/23 11:21:12");

  script_xref(name:"FEDORA", value:"2019-e50f92e4c1");

  script_name(english:"Fedora 30 : glpi (2019-e50f92e4c1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 9.4.1.1**

Non exhaustive list of changes :

  - [security] Bad chevrons rendering on dropdowns (#5468)

  - [security] Iframe and forms are rendered in rich text
    contents (#5519)

  - [security] Type juggling authentication bypass (#5520)

  - [security] Malicious images upload (#5580)

  - [security] Password token date was not reset (#5577)

  - [security] Prevent timed attack and enforce cookie
    security (#5562)

  - Search on dropdowns now displays fuzzy matches (#5149)

  - All components were deleted when permanently deleting a
    computer (#5459)

  - Unable to display network ports (#5460, #5461)

  - Preferences not applied (#5372)

  - Unable to use &ldquo;forgotten password&rdquo; feature
    (#5386)

  - And many more!

See
[changelog](https://github.com/glpi-project/glpi/milestone/30?closed=1
) and [minor
changelog](https://github.com/glpi-project/glpi/milestone/33?closed=1)
for details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-e50f92e4c1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/glpi-project/glpi/milestone/30?closed=1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/glpi-project/glpi/milestone/33?closed=1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected glpi package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"glpi-9.4.1.1-1.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glpi");
}
