#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-67.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133031);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2018-18246", "CVE-2018-18247", "CVE-2018-18248", "CVE-2018-18249", "CVE-2018-18250");

  script_name(english:"openSUSE Security Update : icingaweb2 (openSUSE-2020-67)");
  script_summary(english:"Check for the openSUSE-2020-67 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for icingaweb2 to version 2.7.3 fixes the following 
issues :

icingaweb2 update to 2.7.3 :

  - Fixed an issue where servicegroups for roles with
    filtered objects were not available 

icingaweb2 update to 2.7.2 :

  - Performance imrovements and bug fixes

icingaweb2 update to 2.7.1 :

  - Highlight links in the notes of an object 

  - Fixed an issue where sort rules were no longer working

  - Fixed an issue where statistics were shown with an
    anarchist way

  - Fixed an issue where wildcards could no show results 

icingaweb2 update to 2.7.0 :

  - New languages support

  - Now module developers got additional ways to customize
    Icinga Web 2

  - UI enhancements 

icingaweb2 update to 2.6.3 :

  - Fixed various issues with LDAP

  - Fixed issues with timezone

  - UI enhancements 

  - Stability fixes

icingaweb2 update to 2.6.2 :

You can find issues and features related to this release on our
Roadmap. This bugfix release addresses the following topics :

  - Database connections to MySQL 8 no longer fail

  - LDAP connections now have a timeout configuration which
    defaults to 5 seconds

  - User groups are now correctly loaded for externally
    authenticated users

  - Filters are respected for all links in the host and
    service group overviews

  - Fixed permission problems where host and service actions
    provided by modules were missing

  - Fixed a SQL error in the contact list view when
    filtering for host groups

  - Fixed time zone (DST) detection

  - Fixed the contact details view if restrictions are
    active

  - Doc parser and documentation fixes

Fix security issues :

  - CVE-2018-18246: fixed an CSRF in moduledisable
    (boo#1119784)

  - CVE-2018-18247: fixed an XSS via
    /icingaweb2/navigation/add (boo#1119785)

  - CVE-2018-18248: fixed an XSS attack is possible via
    query strings or a dir parameter (boo#1119801)

  - CVE-2018-18249: fixed an injection of PHP ini-file
    directives involves environment variables as channel to
    send out information (boo#1119799)

  - CVE-2018-18250: fixed parameters that can break
    navigation dashlets (boo#1119800)

  - Remove setuid from new upstream spec file for following
    dirs :

    /etc/icingaweb2, /etc/icingaweb/modules,
    /etc/icingaweb2/modules/setup,
    /etc/icingaweb2/modules/translation, /var/log/icingaweb2

icingaweb2 updated to 2.6.1 :

  - You can find issues and features related to this release
    on our
    [Roadmap](https://github.com/Icinga/icingaweb2/milestone
    /51?closed=1).

  - The command audit now logs a command's payload as JSON
    which fixes a
    [bug](https://github.com/Icinga/icingaweb2/issues/3535)
    that has been introduced in version 2.6.0.

icingaweb2 was updated to 2.6.0 :

  - You can find issues and features related to this release
    on our Roadmap.

  - Enabling you to do stuff you couldn't before

  - Support for PHP 7.2 added

  - Support for SQLite resources added

  - Login and Command (monitoring) auditing added with the
    help of a dedicated module

  - Pluginoutput rendering is now hookable by modules which
    allows to render custom icons, emojis and .. cute
    kitties :octocat :

  - Avoiding that you miss something

  - It's now possible to toggle between list- and grid-mode
    for the host- and servicegroup overviews

  - The servicegrid now supports to flip its axes which
    allows it to be put into a landscape mode

  - Contacts only associated with services are visible now
    when restricted based on host filters

  - Negated and combined membership filters now work as
    expected (#2934)

  - A more prominent error message in case the monitoring
    backend goes down

  - The filter editor doesn't get cleared anymore upon
    hitting Enter

  - Making your life a bit easier

  - The tactical overview is now filterable and can be
    safely put into the dashboard

  - It is now possible to register new announcements over
    the REST Api

  - Filtering for custom variables now works in UTF8
    environments

  - Ensuring you understand everything

  - The monitoring health is now beautiful to look at and
    properly behaves in narrow environments

  - Updated German localization

  - Updated Italian localization

  - Freeing you from unrealiable things

  - Removed support for PHP < 5.6

  - Removed support for persistent database connections"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Icinga/icingaweb2/issues/3535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/Icinga/icingaweb2/milestone/51?closed=1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected icingaweb2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingacli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-HTMLPurifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-JShrink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-Parsedown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-dompdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-lessphp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-zf1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php-Icinga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"icingacli-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-common-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-HTMLPurifier-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-JShrink-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-Parsedown-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-dompdf-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-lessphp-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-zf1-2.7.3-lp151.6.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php-Icinga-2.7.3-lp151.6.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icingacli / icingaweb2 / icingaweb2-common / etc");
}
