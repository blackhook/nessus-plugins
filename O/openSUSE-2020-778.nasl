#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-778.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(137227);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/10");

  script_cve_id("CVE-2020-13614");

  script_name(english:"openSUSE Security Update : axel (openSUSE-2020-778)");
  script_summary(english:"Check for the openSUSE-2020-778 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for axel fixes the following issues :

axel was updated to 2.17.8 :

  - CVE-2020-13614: SSL Certificate Hostnames were not
    verified (boo#1172159)

  - Replaced progressbar line clearing with terminal control
    sequence

  - Fixed parsing of Content-Disposition HTTP header

  - Fixed User-Agent HTTP header never being included

Update to version 2.17.7 :

  - Buildsystem fixes

  - Fixed release date for man-pages on BSD

  - Explicitly close TCP sockets on SSL connections too

  - Fixed HTTP basic auth header generation

  - Changed the default progress report to 'alternate output
    mode'

  - Improved English in README.md

Update to version 2.17.6 :

  - Fixed handling of non-recoverable HTTP errors

  - Cleanup of connection setup code

  - Fixed manpage reproducibility issue

  - Use tracker instead of PTS from Debian

Update to version 2.17.5 :

  - Fixed progress indicator misalignment

  - Cleaned up the wget-like progress output code

  - Improved progress output flushing

Update to version 2.17.4 :

  - Fixed build with bionic libc (Android)

  - TCP Fast Open support on Linux

  - TCP code cleanup

  - Removed dependency on libm

  - Data types and format strings cleanup

  - String handling cleanup

  - Format string checking GCC attributes added

  - Buildsystem fixes and improvements

  - Updates to the documentation

  - Updated all translations

  - Fixed Footnotes in documentation

  - Fixed a typo in README.md

Update to version 2.17.3 :

  - Builds now use canonical host triplet instead of `uname
    -s`

  - Fixed build on Darwin / Mac OS X

  - Fixed download loops caused by last byte pointer being
    off by one

  - Fixed linking issues (i18n and posix threads)

  - Updated build instructions

  - Code cleanup

  - Added autoconf-archive to building instructions

Update to version 2.17.2 :

  - Fixed HTTP request-ranges to be zero-based

  - Fixed typo 'too may' -> 'too many'

  - Replaced malloc + memset calls with calloc

  - Sanitize progress bar buffer len passed to memset

Update to version 2.17.1 :

  - Fixed comparison error in axel_divide

  - Make sure maxconns is at least 1

Update to version 2.17 :

  - Fixed composition of URLs in redirections

  - Fixed request range calculation

  - Updated all translations

  - Updated build documentation

  - Major code cleanup

  - Cleanup of alternate progress output

  - Removed global string buffers

  - Fixed min and max macros

  - Moved User-Agent header to conf->add_header

  - Use integers for speed ratio and delay calculation

  - Added support for parsing IPv6 literal hostname

  - Fixed filename extraction from URL

  - Fixed request-target message to proxy

  - Handle secure protocol's schema even with SSL disabled

  - Fixed Content-Disposition filename value decoding

  - Strip leading hyphens in extracted filenames"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172159"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected axel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:axel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:axel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:axel-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"axel-2.17.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"axel-debuginfo-2.17.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"axel-debugsource-2.17.8-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "axel / axel-debuginfo / axel-debugsource");
}
