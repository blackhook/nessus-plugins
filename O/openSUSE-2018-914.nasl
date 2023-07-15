#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-914.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112137);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14574");

  script_name(english:"openSUSE Security Update : python-Django (openSUSE-2018-914)");
  script_summary(english:"Check for the openSUSE-2018-914 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-Django to version 2.08 fixes the following
issues :

The following security vulnerability was fixed :

  - CVE-2018-14574: Fixed an redirection vulnerability in
    CommonMiddleware (boo#1102680)

The following other bugs were fixed :

  - Fixed a regression in Django 2.0.7 that broke the regex
    lookup on MariaDB

  - Fixed a regression where django.template.Template
    crashed if the template_string argument is lazy

  - Fixed __regex and __iregex lookups with MySQL

  - Fixed admin check crash when using a query expression in
    ModelAdmin.ordering

  - Fixed admin changelist crash when using a query
    expression without asc() or desc() in the page&rsquo;s
    ordering

  - Fixed a regression that broke custom template filters
    that use decorators

  - Fixed detection of custom URL converters in included
    pattern

  - Fixed a regression that added an unnecessary subquery to
    the GROUP BY clause on MySQL when using a RawSQL
    annotation

  - Fixed WKBWriter.write() and write_hex() for empty
    polygons on GEOS 3.6.1+

  - Fixed a regression in Django 1.10 that could result in
    large memory usage when making edits using
    ModelAdmin.list_editable

  - Corrected the import paths that inspectdb generates for
    django.contrib.postgres fields

  - Fixed crashes in django.contrib.admindocs when a view is
    a callable object, such as
    django.contrib.syndication.views.Feed

  - Fixed a regression in Django 1.11.12 where
    QuerySet.values() or values_list() after combining an
    annotated and unannotated queryset with union(),
    difference(), or intersection() crashed due to
    mismatching columns"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102680"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-Django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-Django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"python3-Django-2.0.8-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-Django");
}
