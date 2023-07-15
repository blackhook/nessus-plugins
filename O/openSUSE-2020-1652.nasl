#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1652.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141387);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_cve_id("CVE-2020-8154", "CVE-2020-8155", "CVE-2020-8183", "CVE-2020-8228", "CVE-2020-8233");

  script_name(english:"openSUSE Security Update : nextcloud (openSUSE-2020-1652)");
  script_summary(english:"Check for the openSUSE-2020-1652 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for nextcloud fixes the following issues :

nextcloud version 20.0.0 fix some security issues :

  - NC-SA-2020-037 PIN for passwordless WebAuthm is asked
    for but not verified

  - NC-SA-2020-033 (CVE-2020-8228) Missing rate limit on
    signup page

  - NC-SA-2020-029 (CVE-2020-8233, boo#1177346) Re-Sharing
    allows increase of privileges

  - NC-SA-2020-026 Passowrd of share by mail is not hashed
    when given on the create share call

  - NC-SA-2020-023 Increase random used for encryption

  - Update to 19.0.3

  - Fix possible leaking scope in Flow (server#22410)

  - Combine body-login rules in theming and fix twofactor
    and guest styling on bright colors (server#22427)

  - Show better quota warning for group folders and external
    storage (server#22442)

  - Add php docs build script (server#22448)

  - Fix clicks on actions menu of non opaque file rows in
    acceptance tests (server#22503)

  - Fix writing BLOBs to postgres with recent contacts
    interaction (server#22515)

  - Set the mount id before calling storage wrapper
    (server#22519)

  - Fix S3 error handling (server#22521)

  - Only disable zip64 if the size is known (server#22537)

  - Change free space calculation (server#22553)

  - Do not keep the part file if the forbidden exception has
    no retry set (server#22560)

  - Fix app password updating out of bounds (server#22569)

  - Use the correct root to determinate the webroot for the
    resource (server#22579)

  - Upgrade icewind/smb to 3.2.7 (server#22581)

  - Bump elliptic from 6.4.1 to 6.5.3 (notifications#732)

  - Fixes regression that prevented you from toggling the
    encryption flag (privacy#489)

  - Match any non-whitespace character in filesystem pattern
    (serverinfo#229)

  - Catch StorageNotAvailable exceptions (text#1001)

  - Harden read only check on public endpoints (text#1017)

  - Harden check when using token from memcache (text#1020)

  - Sessionid is an int (text#1029)

  - Only overwrite Ctrl-f when text is focussed (text#990)

  - Set the X-Requested-With header on dav requests
    (viewer#582)

  - Update to 19.0.2

  - [stable19] lower minimum search length to 2 characters
    (server#21782)

  - [stable19] Call openssl_pkey_export with $config and log
    errors. (server#21804)

  - [stable19] Improve error reporting on sharing errors
    (server#21806)

  - [stable19] Do not log RequestedRangeNotSatisfiable
    exceptions in DAV (server#21840)

  - [stable19] Fix parsing of language code (server#21857)

  - [stable19] fix typo in revokeShare() (server#21876)

  - [stable19] Discourage webauthn user interaction
    (server#21917)

  - [stable19] Encryption is ready if master key is enabled
    (server#21935)

  - [stable19] Disable fragile comments tests (server#21939)

  - [stable19] Do not double encode the userid in webauthn
    login (server#21953)

  - [stable19] update icewind/smb to 3.2.6 (server#21955)

  - [stable19] Respect default share permissions
    (server#21967)

  - [stable19] allow admin to configure the max trashbin
    size (server#21975)

  - [stable19] Fix risky test in twofactor_backupcodes
    (server#21978)

  - [stable19] Fix PHPUnit deprecation warnings
    (server#21981)

  - [stable19] fix moving files from external storage to
    object store trashbin (server#21983)

  - [stable19] Ignore whitespace in sharing by mail
    (server#21991)

  - [stable19] Properly fetch translation for remote wipe
    confirmation dialog (server#22036)

  - [stable19] parse_url returns null in case a parameter is
    not found (server#22044)

  - Bump elliptic from 6.5.2 to 6.5.3 (server#22050)

  - [stable19] Correctly remove usergroup shares on removing
    group members (server#22053)

  - [stable19] Fix height to big for iPhone when using many
    apps (server#22064)

  - [stable19] reset the cookie internally in new API when
    abandoning paged results op (server#22069)

  - [stable19] Add Guzzle's InvalidArgumentException
    (server#22070)

  - [stable19] contactsmanager shall limit number of results
    early (server#22091)

  - [stable19] Fix browser freeze on long password input
    (server#22094)

  - [stable19] Search also the email and displayname in user
    mangement for groups (server#22118)

  - [stable19] Ensured large image is unloaded from memory
    when generating previews (server#22121)

  - [stable19] fix display of remote users in incoming share
    notifications (server#22131)

  - [stable19] Reuse cache for directory mtime/size if
    filesystem changes can be ignored (server#22171)

  - [stable19] Remove unexpected argument (server#22178)

  - [stable19] Do not exit if available space cannot be
    determined on file transfer (server#22181)

  - [stable19] Fix empty 'more' apps navigation after
    installing an app (server#22183)

  - [stable19] Fix default log_rotate_size in
    config.sample.php (server#22192)

  - [stable19] shortcut in reading nested group members when
    IN_CHAIN is available (server#22203)

  - [stable19] Fix chmod on file descriptor (server#22208)

  - [stable19] Do clearstatcache() on rmdir (server#22209)

  - [stable19] SSE enhancement of file signature
    (server#22210)

  - [stable19] remove logging message carrying no valuable
    information (server#22215)

  - [stable19] Add app config option to disable 'Email was
    changed by admin' activity (server#22232)

  - [stable19] Delete chunks if the move on an upload failed
    (server#22239)

  - [stable19] Silence duplicate session warnings
    (server#22247)

  - [3rdparty] Doctrine: Fix unquoted stmt fragments
    backslash escaping (server#22252)

  - [stable19] Allow to disable share emails (server#22300)

  - [stable19] Show disabled user count in occ user:report
    (server#22302)

  - Bump 3rdparty to last stable19 commit (server#22303)

  - [stable19] fixing a logged deprecation message
    (server#22309)

  - [stable19] CalDAV: Add ability to limit sharing to owner
    (server#22333)

  - [stable19] Only copy the link when updating a share or
    no password was forced (server#22337)

  - [stable19] Remove encryption option for nextcloud
    external storage (server#22341)

  - [stable19] l10n:Correct appid for WebAuthn
    (server#22348)

  - [stable19] Properly search for users when limittogroups
    is enabled (server#22355)

  - [stable19] SSE: make legacy format opt in (server#22381)

  - [stable19] Update the CRL (server#22387)

  - [stable19] Fix missing FN from federated contact
    (server#22400)

  - [stable19] fix event icon sizes and text alignment
    (server#22414)

  - [stable19] Bump stecman/symfony-console-completion from
    0.8.0 to 0.11.0 (3rdparty#457)

  - [stable19] Add Guzzle's InvalidArgumentException
    (3rdparty#474)

  - [stable19] Doctrine: Fix unquoted stmt fragments
    backslash escaping (3rdparty#486)

  - [stable19] Fix cypress (viewer#545)

  - Move to webpack vue global config & bump deps
    (viewer#558)

  - Update to 19.0.1

  - Security update Fix (CVE-2020-8183, NC-SA-2020-026,
    CWE-256) A logic error in Nextcloud Server 19.0.0 caused
    a plaintext storage of the share password when it was
    given on the initial create API call.

  - Update to 19.0.0

  - Changes Nextcloud Hub v19, code name &ldquo;home
    office&rdquo;, represents a big step forward for remote
    collaboration in teams. This release brings document
    collaboration to video chats, introduces password-less
    login and improves performance. As this is a major
    release, the changelog is too long to put here. Users
    can look at github milestones to find what has been
    merged. A quick overview of what is new :

  - password-less authentication and many other security
    measures

  - Talk 9 with built-in office document editing courtesy of
    Collabora, a grid view & more

  - MUCH improved performance, Deck integration in Calendar,
    guest account groups and more!"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177346"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected nextcloud package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"nextcloud-20.0.0-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nextcloud-20.0.0-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nextcloud");
}
