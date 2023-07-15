#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1707.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141925);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-12108", "CVE-2020-12137", "CVE-2020-15011");

  script_name(english:"openSUSE Security Update : mailman (openSUSE-2020-1707)");
  script_summary(english:"Check for the openSUSE-2020-1707 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mailman to version 2.1.34 fixes the following issues :

  - The fix for lp#1859104 can result in ValueError being
    thrown on attempts to subscribe to a list. This is fixed
    and extended to apply REFUSE_SECOND_PENDING to
    unsubscription as well. (lp#1878458)

  - DMARC mitigation no longer misses if the domain name
    returned by DNS contains upper case. (lp#1881035)

  - A new WARN_MEMBER_OF_SUBSCRIBE setting can be set to No
    to prevent mailbombing of a member of a list with
    private rosters by repeated subscribe attempts.
    (lp#1883017)

  - Very long filenames for scrubbed attachments are now
    truncated. (lp#1884456)

  - A content injection vulnerability via the private login
    page has been fixed. CVE-2020-15011 (lp#1877379,
    bsc#1173369)

  - A content injection vulnerability via the options login
    page has been discovered and reported by Vishal Singh.
    CVE-2020-12108 (lp#1873722, bsc#1171363)

  - Bounce recognition for a non-compliant Yahoo format is
    added.

  - Archiving workaround for non-ascii in string.lowercase
    in some Python packages is added.

  - Thanks to Jim Popovitch, there is now a
    dmarc_moderation_addresses list setting that can be used
    to apply dmarc_moderation_action to mail From: addresses
    listed or matching listed regexps. This can be used to
    modify mail to addresses that don't accept external mail
    From: themselves.

  - There is a new MAX_LISTNAME_LENGTH setting. The fix for
    lp#1780874 obtains a list of the names of all the all
    the lists in the installation in order to determine the
    maximum length of a legitimate list name. It does this
    on every web access and on sites with a very large
    number of lists, this can have performance implications.
    See the description in Defaults.py for more information.

  - Thanks to Ralf Jung there is now the ability to add text
    based captchas (aka textchas) to the listinfo subscribe
    form. See the documentation for the new CAPTCHA setting
    in Defaults.py for how to enable this. Also note that if
    you have custom listinfo.html templates, you will have
    to add a <mm-captcha-ui> tag to those templates to make
    this work. This feature can be used in combination with
    or instead of the Google reCAPTCHA feature added in
    2.1.26.

  - Thanks to Ralf Hildebrandt the web admin Membership
    Management section now has a feature to sync the list's
    membership with a list of email addresses as with the
    bin/sync_members command.

  - There is a new drop_cc list attribute set from
    DEFAULT_DROP_CC. This controls the dropping of addresses
    from the Cc: header in delivered messages by the
    duplicate avoidance process. (lp#1845751)

  - There is a new REFUSE_SECOND_PENDING mm_cfg.py setting
    that will cause a second request to subscribe to a list
    when there is already a pending confirmation for that
    user. This can be set to Yes to prevent mailbombing of a
    third-party by repeatedly posting the subscribe form.
    (lp#1859104)

  - Fixed the confirm CGI to catch a rare TypeError on
    simultaneous confirmations of the same token.
    (lp#1785854)

  - Scrubbed application/octet-stream MIME parts will now be
    given a .bin extension instead of .obj. CVE-2020-12137
    (lp#1886117)

  - Added bounce recognition for a non-compliant opensmtpd
    DSN with Action: error. (lp#1805137)

  - Corrected and augmented some security log messages.
    (lp#1810098)

  - Implemented use of QRUNNER_SLEEP_TIME for bin/qrunner

    --runner=All. (lp#1818205)

  - Leading/trailing spaces in provided email addresses for
    login to private archives and the user options page are
    now ignored. (lp#1818872)

  - Fixed the spelling of the --no-restart option for
    mailmanctl.

  - Fixed an issue where certain combinations of charset and
    invalid characters in a list's description could produce
    a List-ID header without angle brackets. (lp#1831321)

  - With the Postfix MTA and virtual domains, mappings for
    the site list -bounces and -request addresses in each
    virtual domain are now added to data/virtual-mailman
    (-owner was done in 2.1.24). (lp#1831777)

  - The paths.py module now extends sys.path with the result
    of site.getsitepackages() if available. (lp#1838866)

  - A bug causing a UnicodeDecodeError in preparing to send
    the confirmation request message to a new subscriber has
    been fixed. (lp#1851442)

  - The SimpleMatch heuristic bounce recognizer has been
    improved to not return most invalid email addresses.
    (lp#1859011)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173369"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected mailman packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12137");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mailman-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"mailman-2.1.34-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mailman-debuginfo-2.1.34-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"mailman-debugsource-2.1.34-lp152.7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman / mailman-debuginfo / mailman-debugsource");
}
