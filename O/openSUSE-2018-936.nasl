#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-936.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112141);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-3780");

  script_name(english:"openSUSE Security Update : nextcloud (openSUSE-2018-936)");
  script_summary(english:"Check for the openSUSE-2018-936 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nextcloud to version 13.0.5 fixes the following 
issues :

Security issues fixed :

  - CVE-2018-3780: Fixed a missing sanitization of search
    results for an autocomplete field that could lead to a
    stored XSS requiring user-interaction. The missing
    sanitization only affected user names, hence malicious
    search results could only be crafted by authenticated
    users. (boo#1105598)

Other bugs fixed :

  - Fix highlighting of the upload drop zone

  - Apply ldapUserFilter on members of group

  - Make the DELETION of groups match greedy on the groupID

  - Add parent index to share table

  - Log full exception in cron instead of only the message

  - Properly lock the target file on dav upload when not
    using part files

  - LDAP backup server should not be queried when auth fails

  - Fix filenames in sharing integration tests

  - Lower log level for quota manipulation cases

  - Let user set avatar in nextcloud if LDAP provides
    invalid image data

  - Improved logging of smb connection errors

  - Allow admin to disable fetching of avatars as well as a
    specific attribute

  - Allow to disable encryption

  - Update message shown when unsharing a file

  - Fixed English grammatical error on Settings page.

  - Request a valid property for DAV opendir

  - Allow updating the token on session regeneration

  - Prevent lock values from going negative with memcache
    backend

  - Correctly handle users with numeric user ids

  - Correctly parse the subject parameters for link
    (un)shares of calendars

  - Fix 'parsing' of email-addresses in comments and chat
    messages

  - Sanitize parameters in createSessionToken() while
    logging

  - Also retry rename operation on InvalidArgumentException

  - Improve url detection in comments

  - Only bind to ldap if configuration for the first server
    is set

  - Use download manager from PDF.js to download the file

  - Fix trying to load removed scripts

  - Only pull for new messages if the session is allowed to
    be kept alive

  - Always push object data

  - Add prioritization for Talk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105598"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nextcloud package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/26");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"nextcloud-13.0.5-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nextcloud-13.0.5-12.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nextcloud");
}
