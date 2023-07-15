#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1822.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142560);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/10");

  script_cve_id("CVE-2020-15917");

  script_name(english:"openSUSE Security Update : claws-mail (openSUSE-2020-1822)");
  script_summary(english:"Check for the openSUSE-2020-1822 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for claws-mail fixes the following issues :

  - Additional cleanup of the template handling

claws-mail was updated to 3.17.8 (boo#1177967)

  - Shielded template's |program() and |attach_program() so
    that the command-line that is executed does not allow
    sequencing such as with && || ;, preventing possible
    execution of nasty, or at least unexpected, commands

  - bug fixes: claws#4376

  - updated English, French, and Spanish manuals

  - Update to 3.17.7 

  - Image Viewer: Image attachments, when displayed, are now
    resized to fit the available width rather than the
    available height.

  - -d is now an alias to --debug.

  - Libravatar plugin: New styles supported: Robohash and
    Pagan.

  - SpamAssassin plugin: The 'Maximum size' option now
    matches SpamAssassin's maximum; it can now handle
    messages up to 256MB.

  - LiteHTML viewer plugin: The UI is now translatable. Bug
    fixes :

  - bug 4313, 'Recursion stack overflow with rebuilding
    folder tree'

  - bug 4372, '[pl_PL] Crash after 'Send later' without
    recipient and then 'Close''

  - bug 4373, 'attach mailto URI double free'

  - bug 4374, 'insert mailto URI misses checks'

  - bug 4384, 'U+00AD (soft hyphen) changed to space in
    Subject'

  - bug 4386, 'Allow Sieve config without userid without
    warning'

  - Add missing SSL settings when cloning accounts.

  - Parsing of command-line arguments.

  - PGP Core plugin: fix segv in address completion with a
    keyring.

  - Libravatar plugin: fixes to image display.

  - Disable python-gtk plugin on suse_version > 1500: still
    relying on python2, which is EOL.

  - Update to 3.17.6 :

  - It is now possible to 'Inherit Folder properties and
    processing rules from parent folder' when creating new
    folders with the move message and copy message
    dialogues.

  - A Phishing warning is now shown when copying a phishing
    URL, (in addition to clicking a phishing URL).

  - The progress window when importing an mbox file is now
    more responsive.

  - A warning dialogue is shown if the selected privacy
    system is 'None' and automatic signing amd/or encrypting
    is enabled.

  - Python plugin: pkgconfig is now used to check for
    python2. This enables the Python plugin (which uses
    python2) to be built on newer systems which have both
    python2 and python3. Bug fixes :

  - bug 3922, 'minimize to tray on startup not working'

  - bug 4220, 'generates files in cache without content'

  - bug 4325, 'Following redirects when retrieving image'

  - bug 4342, 'Import mbox file command doesn't work twice
    on a row'

  - fix STARTTLS protocol violation

  - fix initial debug line

  - fix fat-fingered crash when v (hiding msgview) is
    pressed just before c (check signature)

  - fix non-translation of some Templates strings

  - Update to 3.17.5

  + Inline Git patches now have colour syntax highlighting
    The colours of these, and patch attachments, are
    configurable on the 'Other' tab of the Display/Colors
    page of the general preferences.

  + The previously hidden preference, 'summary_from_show',
    is now configurable within the UI, on the 'Message List'
    tab of the Display/Summaries page of the general
    preferences, 'Displayed in From column [ ]'.

  + 'Re-edit' has been added to the message context menu
    when in the Drafts folder.

  + Additional Date header formats are supported :

  - weekday, month, day, hh, mm, ss, year, zone

  - weekday, month, day, hh, mm, ss, year

  + LiteHtml viewer plugin: scrolling with the keyboard has
    been implemented.

  + The included tools/scripts have been updated :

  - eud2gc.py converted to Python 3

  - tbird2claws.py converted to Python 3

  - tbird2claws.py converted to Python 3

  - google_search.pl has been replaced with ddg_search.pl
    (that is, duckduckgo.com instead of google.com)

  - fix_date.sh and its documentation have been updated 

  - multiwebsearch.pl 'fm' (freshmeat.net) has been removed;
    'google' has been replaced by 'ddg'

  - the outdated OOo2claws-mail.pl script has been removed

  + Updated manuals

  + Updated translations: British English, Catalan, Czech,
    Danish, Dutch, French, German, Russian, Slovak, Spanish,
    Swedish, Traditional Chinese, Turkish

  + bug fixes: claws#2131, claws#4237, claws#4239,
    claws#4248, claws#4253, claws#4257, claws#4277,
    claws#4278, claws#4305

  + Misc bugs fixed :

  - Fix crash in litehtml_viewer when tag has no href

  - removed 'The following file has been attached...'
    dialogue

  - MBOX import: give a better estimation of the time left
    and grey out widgets while importing

  - Fixed 'vcard.c:238:2: warning: &lsquo;strncpy&rsquo;
    output truncate before terminating nul copying as many
    bytes from a string as its length'

  - RSSyl: Fix handling deleted feed items where modified
    and published dates do not match 

  - fix bolding of target folder

  - when creating a new account, don't pre-fill data from
    the default account

  - respect 'default selection' settings when moving a msg
    with manual filtering

  - Fix printing of empty pages when the selected part is
    rendered with a plugin not implementing print

  - Addressbook folder selection dialogs: make sure folder
    list is sorted and apply global prefs to get stripes in
    lists.

  - when user cancels the GPG signing passphrase dialogue,
    don't bother the user with an 'error' dialogue

  - Fix imap keyword search. Libetpan assumes keyword search
    is a MUST but RFC states it is a MAY. Fix advanced
    search on MS Exchange

  - fix SHIFT+SPACE in msg list, moving in reverse

  - revert pasting images as attachments

  - Fix help about command-line arguments that require a
    parameter.

  - Printing: only print as plain text if the part is of
    type text

  - fix a segfault with default info icon when trying to
    print a non-text part.

  - Add a test on build-time libetpan version to require the
    proper version at run-time (boo#1157594)

  - Move 'Mark all read/unread' menu entries where they
    belong. remove-MarkAll-from-message-menu.patch
    (claws#4278) add-MarkAll-to-folder-menu.patch
    (claws#4278)

  - Make litehtml plugin build on Tumbleweed.

  - Update to 3.17.4 :

  - New HTML viewer plugin: Litehtml viewer

  - Added option 'Enable keyboard shortcuts' to the
    'Keyboard shortcuts' frame on
    /Configuration/Preferences/Other/Miscellaneous

  - Compose: implemented copying of attached images to
    clipboard

  - Compose: images and text/uri-list (files) can now be
    attached by pasting into the Compose window

  - Python plugin: window sizes are now remembered for the
    Python console, the 'Open URLs' and the 'Set mailbox
    order' windows.

  - Fancy plugin: the download-link feature now follows
    redirections

  - MBOX export: the Enter key in the dialogue now starts
    the export

  - The date (ISO format) has been added to log timestamps

  - Update translations

  - bug 1920, 'No automatic NNTP filtering'

  - bug 2045, 'address book blocks focus on email window'

  - bug 2131, 'Focus stealing after mail check'

  - bug 2627, 'Filtering does not work on NNTP'

  - bug 3070, 'misbehaving text wrapping when URL chars are
    present'

  - bug 3838, 'Canceled right-click on message list leaves
    UI in inconsistent state'

  - bug 3977, 'Fix crashes when some external APIs fail'

  - bug 3979, 'Hang (with killing needed) during action
    which extracts attachments'

  - bug 4029, 'segfault after deleting message in a window'

  - bug 4031, 'fingerprint in SSL/TLS certificates for ...
    (regress error)'

  - bug 4037, 'Fix some small issues'

  - bug 4142, 'Translation error on Russian'

  - bug 4145, 'proxy server for sending doesn't work'

  - bug 4155, 'remember directory of last saving'

  - bug 4166, 'corrupted double-linked list'

  - bug 4167, 'Max line length exceeded when forwarding
    mail'

  - bug 4188, 'STL file is sent not as an attachment but as
    its base64 representation in plaintext'

  - CID 1442278, 'impossible to trigger buffer overflow'

  - Make key accelerators from menu work in addressbook
    window

  - save checkbox choices of display/summaries/defaults
    prefs

  - Do not throw an error when cancelling 'Save email
    as...'.

  - occasional crash on drag'n'drop of msgs

  - possible stack overflow in vcalendar's Curl data handler

  - crash when LDAP address source is defined in index, but

  - support is disabled

  - crash in Fancy plugin if one of the MIME parts has no

  - -ID

  - a few small memory leaks in scan_mailto_url()

  - configure script for rare cases where python is not
    installed

  - incorrect charset conversion in sc_html_read_line().

  - markup in 'key not fully trusted' warning in pgpcore

  - use after free in rare code path in rssyl_subscribe()

  - several memory leaks

  - verify_folderlist_xml() for fresh starts

  - printf formats for size_t and goffset arguments.

  - alertpanel API use in win32 part of mimeview.c

  - pid handling in debug output of kill_children_cb()

  - incorrect pointer arithmetic in w32_filesel.c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177967"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected claws-mail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:claws-mail-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"claws-mail-3.17.8-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"claws-mail-debuginfo-3.17.8-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"claws-mail-debugsource-3.17.8-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"claws-mail-devel-3.17.8-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"claws-mail-lang-3.17.8-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"claws-mail-3.17.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"claws-mail-debuginfo-3.17.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"claws-mail-debugsource-3.17.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"claws-mail-devel-3.17.8-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"claws-mail-lang-3.17.8-lp152.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "claws-mail / claws-mail-debuginfo / claws-mail-debugsource / etc");
}
