#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-1301.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57954);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-4885", "CVE-2012-0830");
  script_bugtraq_id(51193, 51830);
  script_xref(name:"FEDORA", value:"2012-1301");

  script_name(english:"Fedora 15 : maniadrive-1.2-32.fc15.2 / php-5.3.10-1.fc15 / php-eaccelerator-0.9.6.1-9.fc15.2 (2012-1301)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update contains the latest release of PHP, 5.3.10, which fixes a
security issue.

A security fix introduced in PHP 5.3.9 allowed a remote user to crash
the PHP interpreter, or possibly, execute arbitrary code.
(CVE-2012-0830)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=786686"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?446b5504"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8290461"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073230.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f43a2ff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected maniadrive, php and / or php-eaccelerator
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-eaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/15");
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
if (rpm_check(release:"FC15", reference:"maniadrive-1.2-32.fc15.2")) flag++;
if (rpm_check(release:"FC15", reference:"php-5.3.10-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"php-eaccelerator-0.9.6.1-9.fc15.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / php / php-eaccelerator");
}
