#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-13920.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85698);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-7444", "CVE-2015-6727", "CVE-2015-6728", "CVE-2015-6729", "CVE-2015-6730", "CVE-2015-6731", "CVE-2015-6732", "CVE-2015-6733", "CVE-2015-6734", "CVE-2015-6735", "CVE-2015-6736", "CVE-2015-6737");
  script_xref(name:"FEDORA", value:"2015-13920");

  script_name(english:"Fedora 23 : mediawiki-1.25.2-2.fc23 (2015-13920)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - (T94116) SECURITY: Compare API watchlist token in
    constant time * (T97391) SECURITY: Escape error message
    strings in thumb.php * (T106893) SECURITY: Don't leak
    autoblocked IP addresses on Special:DeletedContributions
    * (T102562) Fix InstantCommons parameters to handle the
    new HTTPS-only policy of Wikimedia Commons. * (T100767)
    Setting a configuration setting for skin or extension to
    false in LocalSettings.php was not working. * (T100635)
    API action=opensearch json output no longer breaks when
    $wgDebugToolbar is enabled. * (T102522) Using an
    extension.json or skin.json file which has a
    'manifest_version' property for 1.26 compatability will
    no longer trigger warnings. * (T86156) Running
    updateSearchIndex.php will not throw an error as
    page_restrictions has been added to the locked table
    list. * Special:Version would throw notices if using SVN
    due to an incorrectly named variable. Add an additional
    check that an index is defined.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1253280"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-August/165193.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?405b8c5a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (rpm_check(release:"FC23", reference:"mediawiki-1.25.2-2.fc23")) flag++;


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
