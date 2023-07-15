#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-05cb6287b7.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101564);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2017-05cb6287b7");

  script_name(english:"Fedora 26 : mediawiki (2017-05cb6287b7)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"https://www.mediawiki.org/wiki/Release_notes/1.28#MediaWiki_1.28.1

Changes since 1.28.0

  - $wgRunJobsAsync is now false by default (T142751). This
    change only affects wikis with $wgJobRunRate > 0.

  - Fix fatal from 'WaitConditionLoop' not being found,
    experienced when a wiki has more than one database
    server setup.

  - (T152717) Better escaping for PHP mail() command

  - (T154670) A missing method causing the MySQL installer
    to fatal in rare circumstances was restored.

  - (T154672) Un-deprecate ArticleAfterFetchContentObject
    hook.

  - (T158766) Avoid SQL error on MSSQL when using
    selectRowCount()

  - (T145635) Fix too long index error when installing with
    MSSQL

  - (T156184) $wgRawHtml will no longer apply to
    internationalization messages.

  - (T160519) CACHE_ANYTHING will not be CACHE_ACCEL if no
    accelerator is installed.

  - (T154872) Fix incorrect ar_usertext_timestamp index
    names in new 1.28 installs.

  - (T109140) (T122209) SECURITY: Special:UserLogin and
    Special:Search allow redirect to interwiki links.

  - (T144845) SECURITY: XSS in
    SearchHighlighter::highlightText() when
    $wgAdvancedSearchHighlighting is true.

  - (T125177) SECURITY: API parameters may now be marked as
    'sensitive' to keep their values out of the logs.

  - (T150044) SECURITY: 'Mark all pages visited' on the
    watchlist now requires a CSRF token.

  - (T156184) SECURITY: Escape content model/format url
    parameter in message.

  - (T151735) SECURITY: SVG filter evasion using default
    attribute values in DTD declaration.

  - (T161453) SECURITY: LocalisationCache will no longer use
    the temporary directory in it's fallback chain when
    trying to work out where to write the cache.

  - (T48143) SECURITY: Spam blacklist ineffective on encoded
    URLs inside file inclusion syntax's link parameter.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-05cb6287b7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mediawiki package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^26([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 26", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC26", reference:"mediawiki-1.28.1-2.fc26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mediawiki");
}
