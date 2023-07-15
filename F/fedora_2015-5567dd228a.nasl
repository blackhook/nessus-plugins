#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-5567dd228a.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89243);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2015-5567dd228a");

  script_name(english:"Fedora 23 : mediawiki-1.26.2-1.fc23 (2015-5567dd228a)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes since 1.26.1 * (bug T121892) Various special pages resulted in
fatal errors. Changes since 1.26.0 * (bug T117899) SECURITY:
$wgArticlePath can no longer be set to relative paths that do not
begin with a slash. This enabled trivial XSS attacks. Configuration
values such as 'http://my.wiki.com/wiki/$1' are fine, as are
'/wiki/$1'. A value such as '$1' or 'wiki/$1' is not and will now
throw an error * (bug T119309) SECURITY: Use hash_compare() for edit
token comparison * (bug T118032) SECURITY: Don't allow cURL to
interpret POST parameters starting with '@' as file uploads * (bug
T115522) SECURITY: Passwords generated by User::randomPassword() can
no longer be shorter than $wgMinimalPasswordLength * (bug T97897)
SECURITY: Improve IP parsing and trimming. Previous behavior could
result in improper blocks being issued * (bug T109724) SECURITY:
Special:MyPage, Special:MyTalk, Special:MyContributions and related
pages no longer use HTTP redirects and are now redirected by MediaWiki
* Fixed ConfigException in ExpandTemplates due to AlwaysUseTidy. *
Fixed stray literal \n in Special:Search. * Fix issue that breaks HHVM
Repo Authorative mode. * (bug T120267) Work around APCu memory
corruption bug

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://my.wiki.com/wiki/$1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wiki.com/index.htm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1293847"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-January/174806.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f60f4a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC23", reference:"mediawiki-1.26.2-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mediawiki");
}