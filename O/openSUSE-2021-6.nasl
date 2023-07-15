#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-6.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145283);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/25");

  script_name(english:"openSUSE Security Update : privoxy (openSUSE-2021-6)");
  script_summary(english:"Check for the openSUSE-2021-6 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for privoxy fixes the following issues :

privoxy was updated to 3.0.29 :

  - Fixed memory leaks when a response is buffered and the
    buffer limit is reached or Privoxy is running out of
    memory. OVE-20201118-0001

  - Fixed a memory leak in the show-status CGI handler when
    no action files are configured OVE-20201118-0002

  - Fixed a memory leak in the show-status CGI handler when
    no filter files are configured OVE-20201118-0003

  - Fixes a memory leak when client tags are active
    OVE-20201118-0004

  - Fixed a memory leak if multiple filters are executed and
    the last one is skipped due to a pcre error
    OVE-20201118-0005

  - Prevent an unlikely dereference of a NULL pointer that
    could result in a crash if accept-intercepted-requests
    was enabled, Privoxy failed to get the request
    destination from the Host header and a memory allocation
    failed. OVE-20201118-0006

  - Fixed memory leaks in the client-tags CGI handler when
    client tags are configured and memory allocations fail.
    OVE-20201118-0007

  - Fixed memory leaks in the show-status CGI handler when
    memory allocations fail OVE-20201118-0008

  - Add experimental https inspection support

  - Use JIT compilation for static filtering for speedup

  - Add support for Brotli decompression, add
    'no-brotli-accepted' filter which prevents the use of
    Brotli compression

  - Add feature to gather exended statistics

  - Use IP_FREEBIND socket option to help with failover

  - Allow to use extended host patterns and vanilla host
    patterns at the same time by prefixing extended host
    patterns with 'PCRE-HOST-PATTERN:'

  - Added 'Cross-origin resource sharing' (CORS) support

  - Add SOCKS5 username/password support

  - Bump the maximum number of action and filter files to
    100 each

  - Fixed handling of filters with 'split-large-forms 1'
    when using the CGI editor.

  - Better detect a mismatch of connection details when
    figuring out whether or not a connection can be reused

  - Don't send a 'Connection failure' message instead of the
    'DNS failure' message

  - Let LOG_LEVEL_REQUEST log all requests

  - Improvements to default Action file

License changed to GPLv3.

  - remove packaging vulnerability boo#1157449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157449"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected privoxy packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"privoxy-3.0.29-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"privoxy-debuginfo-3.0.29-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"privoxy-debugsource-3.0.29-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"privoxy-3.0.29-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"privoxy-debuginfo-3.0.29-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"privoxy-debugsource-3.0.29-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "privoxy / privoxy-debuginfo / privoxy-debugsource");
}
