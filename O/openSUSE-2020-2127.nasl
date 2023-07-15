#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2127.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143462);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-14093", "CVE-2020-14154", "CVE-2020-14954", "CVE-2020-28896");

  script_name(english:"openSUSE Security Update : neomutt (openSUSE-2020-2127)");
  script_summary(english:"Check for the openSUSE-2020-2127 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for neomutt fixes the following issues :

Update neomutt to 20201120. Address boo#1179035, CVE-2020-28896.

  - Security

  - imap: close connection on all failures

  - Features

  - alias: add function to Alias/Query dialogs

  - config: add validators for
    (imap,smtp,pop)_authenticators

  - config: warn when signature file is missing or not
    readable

  - smtp: support for native SMTP LOGIN auth mech

  - notmuch: show originating folder in index

  - Bug Fixes

  - sidebar: prevent the divider colour bleeding out

  - sidebar: fix <sidebar-(next,prev)-new>

  - notmuch: fix query for current email

  - restore shutdown-hook functionality

  - crash in reply-to

  - user-after-free in folder-hook

  - fix some leaks

  - fix application of limits to modified mailboxes

  - write Date header when postponing

  - Translations

  - 100% Lithuanian

  - 100% Czech

  - 70% Turkish

  - Docs

  - Document that $sort_alias affects the query menu

  - Build

  - improve ASAN flags

  - add SASL and S/MIME to --everything

  - fix contrib (un)install

  - Code

  - my_hdr compose screen notifications

  - add contracts to the MXAPI

  - maildir refactoring

  - further reduce the use of global variables

  - Upstream

  - Add $count_alternatives to count attachments inside
    alternatives

  - Changes from 20200925

  - Features

  - Compose: display user-defined headers

  - Address Book / Query: live sorting

  - Address Book / Query: patterns for searching

  - Config: Add '+=' and '-=' operators for String Lists

  - Config: Add '+=' operator for Strings

  - Allow postfix query ':setenv NAME?' for env vars

  - Bug Fixes

  - Fix crash when searching with invalid regexes

  - Compose: Prevent infinite loop of send2-hooks

  - Fix sidebar on new/removed mailboxes

  - Restore indentation for named mailboxes

  - Prevent half-parsing an alias

  - Remove folder creation prompt for POP path

  - Show error if $message_cachedir doesn't point to a valid
    directory

  - Fix tracking LastDir in case of IMAP paths with Unicode
    characters

  - Make sure all mail gets applied the index limit

  - Add warnings to -Q query CLI option

  - Fix index tracking functionality

  - Changed Config

  - Add $compose_show_user_headers (yes)

  - Translations

  - 100% Czech

  - 100% Lithuanian

  - Split up usage strings

  - Build

  - Run shellcheck on hcachever.sh

  - Add the Address Sanitizer

  - Move compose files to lib under compose/

  - Move address config into libaddress

  - Update to latest acutest - fixes a memory leak in the
    unit tests

  - Code

  - Implement ARRAY API

  - Deglobalised the Config Sort functions

  - Refactor the Sidebar to be Event-Driven

  - Refactor the Color Event

  - Refactor the Commands list

  - Make ctx_update_tables private

  - Reduce the scope/deps of some Validator functions

  - Use the Email's IMAP UID instead of an increasing number
    as index

  - debug: log window focus

  - Removed
    neomutt-sidebar-abbreviate-shorten-what-user-sees.patch.
    No longer needed.

  - Update to 20200821 :

  - Bug Fixes

  - fix maildir flag generation

  - fix query notmuch if file is missing

  - notmuch: don't abort sync on error

  - fix type checking for send config variables

  - Changed Config

  - $sidebar_format - Use %D rather than %B for named
    mailboxes

  - Translations

  - 96% Lithuanian

  - 90% Polish

  - fix(sidebar): abbreviate/shorten what user sees

  - Fix sidebar mailbox name display problem. 

  - Update to 20200814 :

  - Notes

  - Add one-liner docs to config items See: neomutt -O -Q
    smart_wrap

  - Remove the built-in editor A large unused and unusable
    feature

  - Security

  - Add mitigation against DoS from thousands of parts
    boo#1179113

  - Features

  - Allow index-style searching in postpone menu

  - Open NeoMutt using a mailbox name

  - Add cd command to change the current working directory

  - Add tab-completion menu for patterns

  - Allow renaming existing mailboxes

  - Check for missing attachments in alternative parts

  - Add one-liner docs to config items

  - Bug Fixes

  - Fix logic in checking an empty From address

  - Fix Imap crash in cmd_parse_expunge()

  - Fix setting attributes with S-Lang

  - Fix: redrawing of $pager_index_lines

  - Fix progress percentage for syncing large mboxes

  - Fix sidebar drawing in presence of indentation + named
    mailboxes

  - Fix retrieval of drafts when 'postponed' is not in the
    mailboxes list

  - Do not add comments to address group terminators

  - Fix alias sorting for degenerate addresses

  - Fix attaching emails

  - Create directories for nonexistent file hcache case

  - Avoid creating mailboxes for failed subscribes

  - Fix crash if rejecting cert

  - Changed Config

  - Add $copy_decode_weed, $pipe_decode_weed,
    $print_decode_weed

  - Change default of $crypt_protected_headers_subject to
    '...'

  - Add default keybindings to history-up/down

  - Translations

  - 100% Czech

  - 100% Spanish

  - Build

  - Allow building against Lua 5.4

  - Fix when sqlite3.h is missing

  - Docs

  - Add a brief section on stty to the manual

  - Update section 'Terminal Keybindings' in the manual

  - Clarify PGP Pseudo-header S<id> duration

  - Code

  - Clean up String API

  - Make the Sidebar more independent

  - De-centralise the Config Variables

  - Refactor dialogs

  - Refactor: Help Bar generation

  - Make more APIs Context-free

  - Adjust the edata use in Maildir and Notmuch

  - Window refactoring

  - Convert libsend to use Config functions

  - Refactor notifications to reduce noise

  - Convert Keymaps to use STAILQ

  - Track currently selected email by msgid

  - Config: no backing global variable

  - Add events for key binding

  - Upstream

  - Fix imap postponed mailbox use-after-free error

  - Speed up thread sort when many long threads exist

  - Fix ~v tagging when switching to non-threaded sorting

  - Add message/global to the list of known 'message' types

  - Print progress meter when copying/saving tagged messages

  - Remove ansi formatting from autoview generated quoted
    replies

  - Change postpone mode to write Date header too

  - Unstuff format=flowed

  - Update to 20200626 :

  - Bug Fixes

  - Avoid opening the same hcache file twice

  - Re-open Mailbox after folder-hook

  - Fix the matching of the spoolfile Mailbox

  - Fix link-thread to link all tagged emails

  - Changed Config

  - Add $tunnel_is_secure config, defaulting to true

  - Upstream

  - Don't check IMAP PREAUTH encryption if $tunnel is in use

  - Add recommendation to use $ssl_force_tls

  - Changes from 20200501 :

  - Security

  - Abort GnuTLS certificate check if a cert in the chain is
    rejected CVE-2020-14154 boo#1172906

  - TLS: clear data after a starttls acknowledgement
    CVE-2020-14954 boo#1173197

  - Prevent possible IMAP MITM via PREAUTH response
    CVE-2020-14093 boo#1172935

  - Features

  - add config operations +=/-= for number,long

  - Address book has a comment field

  - Query menu has a comment field

  - Contrib sample.neomuttrc-starter: Do not echo prompted
    password

  - Bug Fixes

  - make 'news://' and 'nntp://' schemes interchangeable

  - Fix CRLF to LF conversion in base64 decoding

  - Double comma in query

  - compose: fix redraw after history

  - Crash inside empty query menu

  - mmdf: fix creating new mailbox

  - mh: fix creating new mailbox

  - mbox: error out when an mbox/mmdf is a pipe

  - Fix list-reply by correct parsing of List-Post headers

  - Decode references according to RFC2047

  - fix tagged message count

  - hcache: fix keylen not being considered when building
    the full key

  - sidebar: fix path comparison

  - Don't mess with the original pattern when running IMAP
    searches

  - Handle IMAP 'NO' resps by issuing a msg instead of
    failing badly

  - imap: use the connection delimiter if provided

  - Memory leaks

  - Changed Config

  - $alias_format default changed to include %c comment

  - $query_format default changed to include %e extra info

  - Translations

  - 100% Lithuanian

  - 84% French

  - Log the translation in use

  - Docs

  - Add missing commands unbind, unmacro to man pages

  - Build

  - Check size of long using LONG_MAX instead of __WORDSIZE

  - Allow ./configure to not record cflags

  - fix out-of-tree build

  - Avoid locating gdbm symbols in qdbm library

  - Code

  - Refactor unsafe TAILQ returns

  - add window notifications

  - flip negative ifs

  - Update to latest acutest.h

  - test: add store tests

  - test: add compression tests

  - graphviz: email

  - make more opcode info available

  - refactor: main_change_folder()

  - refactor: mutt_mailbox_next()

  - refactor: generate_body()

  - compress: add (min,max)_level to ComprOps

  - emphasise empty loops: '// do nothing'

  - prex: convert is_from() to use regex

  - Refactor IMAP's search routines

  - Update to 20200501 :

  - Bug Fixes

  - Make sure buffers are initialized on error

  - fix(sidebar): use abbreviated path if possible

  - Translations

  - 100% Lithuanian

  - Docs

  - make header cache config more explicit

  - Changes from 20200424 :

  - Bug Fixes

  - Fix history corruption

  - Handle pretty much anything in a URL query part

  - Correctly parse escaped characters in header phrases

  - Fix crash reading received header

  - Fix sidebar indentation

  - Avoid crashing on failure to parse an IMAP mailbox

  - Maildir: handle deleted emails correctly

  - Ensure OP_NULL is always first

  - Translations

  - 100% Czech

  - Build

  - cirrus: enable pcre2, make pkgconf a special case

  - Fix finding pcre2 w/o pkgconf

  - build: tdb.h needs size_t, bring it in with stddef.h

  - Changes from 20200417 :

  - Features

  - Fluid layout for Compose Screen, see:
    vimeo.com/407231157

  - Trivial Database (TDB) header cache backend

  - RocksDB header cache backend

  - Add <sidebar-first> and <sidebar-last> functions

  - Bug Fixes

  - add error for CLI empty emails

  - Allow spaces and square brackets in paths

  - browser: fix hidden mailboxes

  - fix initial email display

  - notmuch: fix time window search.

  - fix resize bugs

  - notmuch: fix entire-thread: update current email pointer

  - sidebar: support indenting and shortening of names

  - Handle variables inside backticks in sidebar_whitelist

  - browser: fix mask regex error reporting

  - Translations

  - 100% Lithuanian

  - 99% Chinese (simplified)

  - Build

  - Use regexes for common parsing tasks: urls, dates

  - Add configure option --pcre2 -- Enable PCRE2 regular
    expressions

  - Add configure option --tdb -- Use TDB for the header
    cache

  - Add configure option --rocksdb -- Use RocksDB for the
    header cache

  - Create libstore (key/value backends)

  - Update to latest autosetup

  - Update to latest acutest.h

  - Rename doc/ directory to docs/

  - make: fix location of .Po dependency files

  - Change libcompress to be more universal

  - Fix test fails on &#x445;32

  - fix uidvalidity to unsigned 32-bit int

  - Code

  - Increase test coverage

  - Fix memory leaks

  - Fix null checks

  - Upstream

  - Buffer refactoring

  - Fix use-after-free in mutt_str_replace()

  - Clarify PGP Pseudo-header S<id> duration

  - Try to respect MUTT_QUIET for IMAP contexts too

  - Limit recurse depth when parsing mime messages

  - Update to 20200320 :

  - Bug Fixes

  - Fix COLUMNS env var

  - Fix sync after delete

  - Fix crash in notmuch

  - Fix sidebar indent

  - Fix emptying trash

  - Fix command line sending

  - Fix reading large address lists

  - Resolve symlinks only when necessary

  - Translations

  - lithuania 100% Lithuanian

  - es 96% Spanish

  - Docs

  - Include OpenSSL/LibreSSL/GnuTLS version in neomutt -v
    output

  - Fix case of GPGME and SQLite

  - Build

  - Create libcompress (lz4, zlib, zstd)

  - Create libhistory

  - Create libbcache

  - Move zstrm to libconn

  - Code

  - Add more test coverage

  - Rename magic to type

  - Use mutt_file_fopen() on config variables

  - Change commands to use intptr_t for data

  - Update to 20200313 :

  - Window layout

  - Sidebar is only visible when it's usable.

  - Features

  - UI: add number of old messages to sidebar_format

  - UI: support ISO 8601 calendar date

  - UI: fix commands that don&rsquo;t need to have a
    non-empty mailbox to be valid

  - PGP: inform about successful decryption of inline PGP
    messages

  - PGP: try to infer the signing key from the From address

  - PGP: enable GPGMe by default

  - Notmuch: use query as name for vfolder-from-query

  - IMAP: add network traffic compression (COMPRESS=DEFLATE,
    RFC4978)

  - Header cache: add support for generic header cache
    compression

  - Bug Fixes

  - Fix uncollapse_jump

  - Only try to perform entire-thread on maildir/mh
    mailboxes

  - Fix crash in pager

  - Avoid logging single new lines at the end of header
    fields

  - Fix listing mailboxes

  - Do not recurse a non-threaded message

  - Fix initial window order

  - Fix leaks on IMAP error paths

  - Notmuch: compose(attach-message): support notmuch
    backend

  - Fix IMAP flag comparison code

  - Fix $move for IMAP mailboxes

  - Maildir: maildir_mbox_check_stats should only update
    mailbox stats if requested

  - Fix unmailboxes for virtual mailboxes

  - Maildir: sanitize filename before hashing

  - OAuth: if 'login' name isn't available use 'user'

  - Add error message on failed encryption

  - Fix a bunch of crashes

  - Force C locale for email date

  - Abort if run without a terminal

  - Changed Config

  - $crypt_use_gpgme - Now defaults to 'yes' (enabled)

  - $abort_backspace - Hitting backspace against an empty
    prompt aborts the prompt

  - $abort_key - String representation of key to abort
    prompts

  - $arrow_string - Use an custom string for arrow_cursor

  - $crypt_opportunistic_encrypt_strong_keys - Enable
    encryption only when strong a key is available

  - $header_cache_compress_dictionary - Filepath to
    dictionary for zstd compression

  - $header_cache_compress_level - Level of compression for
    method

  - $header_cache_compress_method - Enable generic hcache
    database compression

  - $imap_deflate - Compress network traffic

  - $smtp_user - Username for the SMTP server

  - Translations

  - 100% Lithuanian

  - 81% Spanish

  - 78% Russian

  - Build

  - Add libdebug

  - Rename public headers to lib.h

  - Create libcompress for compressed folders code

  - Code

  - Refactor Windows and Dialogs

  - Lots of code tidying

  - Refactor: mutt_addrlist_(search,write)

  - Lots of improvements to the Config code

  - Use Buffers more pervasively

  - Unify API function naming

  - Rename library shared headers

  - Refactor libconn gui dependencies

  - Refactor: init.[ch]

  - Refactor config to use subsets

  - Config: add path type

  - Remove backend deps from the connection code

  - Upstream

  - Allow ~b ~B ~h patterns in send2-hook

  - Rename smime oppenc mode parameter to get_keys_by_addr()

  - Add $crypt_opportunistic_encrypt_strong_keys config var

  - Fix crash when polling a closed ssl connection

  - Turn off auto-clear outside of autocrypt initialization

  - Add protected-headers='v1' to Content-Type when
    protecting headers

  - Fix segv in IMAP postponed menu caused by reopen_allow

  - Adding ISO 8601 calendar date

  - Fix $fcc_attach to not prompt in batch mode

  - Convert remaining mutt_encode_path() call to use struct
    Buffer

  - Fix rendering of replacement_char when Charset_is_utf8

  - Update to latest acutest.h

  - Update to 20191207 :

  - Features :

  - compose: draw status bar with highlights

  - Bug Fixes :

  - crash opening notmuch mailbox

  - crash in mutt_autocrypt_ui_recommendation

  - Avoid negative allocation

  - Mbox new mail

  - Setting of DT_MAILBOX type variables from Lua

  - imap: empty cmdbuf before connecting

  - imap: select the mailbox on reconnect

  - compose: fix attach message

  - Build :

  - make files conditional

  - Code :

  - enum-ify log levels

  - fix function prototypes

  - refactor virtual email lookups

  - factor out global Context

  - Changes from 20191129 :

  - Features :

  - Add raw mailsize expando (%cr)

  - Bug Fixes :

  - Avoid double question marks in bounce confirmation msg

  - Fix bounce confirmation

  - fix new-mail flags and behaviour

  - fix: browser <descend-directory>

  - fix ssl crash

  - fix move to trash

  - fix flickering

  - Do not check hidden mailboxes for new mail

  - Fix new_mail_command notifications

  - fix crash in examine_mailboxes()

  - fix crash in mutt_sort_threads()

  - fix: crash after sending

  - Fix crash in tunnel's conn_close

  - fix fcc for deep dirs

  - imap: fix crash when new mail arrives

  - fix colour 'quoted9'

  - quieten messages on exit

  - fix: crash after failed mbox_check

  - browser: default to a file/dir view when attaching a
    file

  - Changed Config :

  - Change $write_bcc to default off

  - Docs :

  - Add a bit more documentation about sending

  - Clarify $write_bcc documentation.

  - Update documentation for raw size expando

  - docbook: set generate.consistent.ids to make generated
    html reproducible

  - Build :

  - fix build/tests for 32-bit arches

  - tests: fix test that would fail soon

  - tests: fix context for failing idna tests

  - Update to 20191111: Bug fixes :

  - browser: fix directory view

  - fix crash in mutt_extract_token()

  - force a screen refresh

  - fix crash sending message from command line

  - notmuch: use nm_default_uri if no mailbox data

  - fix forward attachments

  - fix: vfprintf undefined behaviour in body_handler

  - Fix relative symlink resolution

  - fix: trash to non-existent file/dir

  - fix re-opening of mbox Mailboxes

  - close logging as late as possible

  - log unknown mailboxes

  - fix crash in command line postpone

  - fix memory leaks

  - fix icommand parsing

  - fix new mail interaction with mail_check_recent"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179113"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected neomutt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14154");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neomutt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neomutt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neomutt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neomutt-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/03");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"neomutt-20201120-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"neomutt-debuginfo-20201120-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"neomutt-debugsource-20201120-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"neomutt-lang-20201120-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"neomutt-20201120-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"neomutt-debuginfo-20201120-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"neomutt-debugsource-20201120-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"neomutt-lang-20201120-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "neomutt / neomutt-debuginfo / neomutt-debugsource / neomutt-lang");
}
