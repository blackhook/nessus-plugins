#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2185.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(129377);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_name(english:"openSUSE Security Update : links (openSUSE-2019-2185)");
  script_summary(english:"Check for the openSUSE-2019-2185 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for links fixes the following issues :

links was updated to 2.20.1 :

  - libevent bug fixes

links was updated to 2.20 :

  - Security bug fixed: when links was connected to tor, it
    would send real dns requests outside the tor network
    when the displayed page contains link elements with
    rel=dns-prefetch boo#1149886

  - stability improvements

  - file urls support local hostnames

  - mouse support improvement

  - improve interaction with Google

  - Support the zstd compression algorithm

  - Use proper cookie expiry

links was updated to 2.19 :

  - Fixed a crash on invalidn IDN URLs

  - Make font selection possible via fontconfig

  - Show certificate authority in Document info box

  - Use international error messages

  - The -dump switch didn't report errors on stdout write

links was updated to 2.18 :

  - Automatically enable tor mode when the socks port is
    9050

  - When in tor mode, invert colors on top line and bottom
    line

  - Fix an incorrect shift in write_ev_queue 

  - Fix runtime error sanitizer warning

  - Add a menu entry to save and load a clipboard

  - Don't synch with Xserver on every pixmap load

  - Fix 'Network Options' bug that caused a timeout

  - Fix a possible integer overflow in decoder_memory_expand

  - Fix possible pointer arithmetics bug if os allocated few
    bytes

  - Add a button to never accept invalid certs for a given
    server

  - Fix incorrect strings -html-t-text-color

  - Add ascii replacement of Romanian S and T with comma

  - Fix a bug when IPv6 control connection to ftp server
    fails links was updated to 2.17 :

  - Fix verifying SSL certificates for numeric IPv6
    addresses

  - Delete the option -ftp.fast - it doesn't always work and
    ftp performance is not an issue anymore

  - Add bold and monospaced Turkish letter 'i' without a dot

  - On OS/2 allocate OpenSSL memory fro the lower heap. It
    fixes SSL on systems with old 16-bit TCP/IP stack

  - Fix IPv6 on OpenVMS Alpha

  - Support mouse scroll wheel in textarea

  - Delete the option -http-bugs.bug-302-redirect - RFC7231
    allows the 'buggy' behavior and defines new codes 307
    and 308 that retain the post data

  - X11 - fixed colormap leak when creating a new window

  - Fixed an infinite loop that happened in graphics mode if
    the user clicked on OK in 'Miscellaneous options' dialog
    and more than one windows were open. This bug was
    introduced in Links 2.15

  - Support 6x6x6 RGB palette in 256-bit color mode on
    framebuffer

  - Implement dithering properly on OS/2 in 15-bit and
    16-bit color mode. In 8-bit mode, Links may optionally
    use a private palette - it improves visual quality of
    Links images, but degrades visual quality of other
    concurrently running programs.

  - Improve scrolling smoothness when the user drags the
    whole document

  - On OS/2, allocate large memory blocks directly (not with
    malloc). It reduces memory waste

  - Fixed a bug that setting terminal title and resizing a
    terminal didn't work on OS/2 and Windows. The bug was
    introduced in Links 2.16 when shutting up coverity
    warnings

  - Set link color to yellow by default

  - Delete the option -http-bugs.bug-post-no-keepalive. It
    was needed in 1999 to avoid some bug in some http server
    and it is not needed anymore

  - Trust Content-Length on HTTP/1.0 redirect requests. This
    fixes hangs with misbehaving servers that honor
    Connection:keep-alive but send out HTTP/1.0 reply
    without Connection: keep-alive. Links thought that they
    don't support keep-alive and waited for the connection
    to close (for example http://www.raspberrypi.org)

  - Use keys 'H' and 'L' to select the top and bottom link
    on the current page

links was updated to 2.16 :

  - Improve handling of the DELETE key

  - Implement the bracketed paste mode

  - Fix various bugs found by coverity

  - Fix a crash in proxy authentication code

  - Fixed internal error 'invalid set_handlers call' on
    framebuffer if links is suspend and terminate at the
    same time"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.raspberrypi.org"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149886"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected links packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:links");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:links-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:links-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"links-2.20.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"links-debuginfo-2.20.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"links-debugsource-2.20.1-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "links / links-debuginfo / links-debugsource");
}
