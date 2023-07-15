#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-443.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147925);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2021-20272", "CVE-2021-20273", "CVE-2021-20274", "CVE-2021-20275", "CVE-2021-20276");

  script_name(english:"openSUSE Security Update : privoxy (openSUSE-2021-443)");
  script_summary(english:"Check for the openSUSE-2021-443 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for privoxy fixes the following issues :

Update to version 3.0.32 :

  - Security/Reliability (boo#1183129)

  - ssplit(): Remove an assertion that could be triggered
    with a crafted CGI request. Commit 2256d7b4d67.
    OVE-20210203-0001. CVE-2021-20272 Reported by: Joshua
    Rogers (Opera)

  - cgi_send_banner(): Overrule invalid image types.
    Prevents a crash with a crafted CGI request if Privoxy
    is toggled off. Commit e711c505c48. OVE-20210206-0001.
    CVE-2021-20273 Reported by: Joshua Rogers (Opera)

  - socks5_connect(): Don't try to send credentials when
    none are configured. Fixes a crash due to a NULL pointer
    dereference when the socks server misbehaves. Commit
    85817cc55b9. OVE-20210207-0001. CVE-2021-20274 Reported
    by: Joshua Rogers (Opera)

  - chunked_body_is_complete(): Prevent an invalid read of
    size two. Commit a912ba7bc9c. OVE-20210205-0001.
    CVE-2021-20275 Reported by: Joshua Rogers (Opera)

  - Obsolete pcre: Prevent invalid memory accesses with an
    invalid pattern passed to pcre_compile(). Note that the
    obsolete pcre code is scheduled to be removed before the
    3.0.33 release. There has been a warning since 2008
    already. Commit 28512e5b624. OVE-20210222-0001.
    CVE-2021-20276 Reported by: Joshua Rogers (Opera)

  - Bug fixes :

  - Properly parse the client-tag-lifetime directive.
    Previously it was not accepted as an obsolete hash value
    was being used. Reported by: Joshua Rogers (Opera)

  - decompress_iob(): Prevent reading of uninitialized data.
    Reported by: Joshua Rogers (Opera).

  - decompress_iob(): Don't advance cur past eod when
    looking for the end of the file name and comment.

  - decompress_iob(): Cast value to unsigned char before
    shifting. Prevents a left-shift of a negative value
    which is undefined behaviour. Reported by: Joshua Rogers
    (Opera)

  - gif_deanimate(): Confirm that that we have enough data
    before doing any work. Fixes a crash when fuzzing with
    an empty document. Reported by: Joshua Rogers (Opera).

  - buf_copy(): Fail if there's no data to write or nothing
    to do. Prevents undefined behaviour 'applying zero
    offset to NULL pointer'. Reported by: Joshua Rogers
    (Opera)

  - log_error(): Treat LOG_LEVEL_FATAL as fatal even when
    --stfu is being used while fuzzing. Reported by: Joshua
    Rogers (Opera).

  - Respect DESTDIR when considering whether or not to
    install config files with '.new' extension.

  - OpenSSL ssl_store_cert(): Fix two error messages.

  - Fix a couple of format specifiers.

  - Silence compiler warnings when compiling with NDEBUG.

  - fuzz_server_header(): Fix compiler warning.

  - fuzz_client_header(): Fix compiler warning.

  - cgi_send_user_manual(): Also reject requests if the
    user-manual directive specifies a https:// URL.
    Previously Privoxy would try and fail to open a local
    file.

  - General improvements :

  - Log the TLS version and the the cipher when debug 2 is
    enabled.

  - ssl_send_certificate_error(): Respect HEAD requests by
    not sending a body.

  - ssl_send_certificate_error(): End the body with a single
    new line.

  - serve(): Increase the chances that the host is logged
    when closing a server socket.

  - handle_established_connection(): Add parentheses to
    clarify an expression Suggested by: David Binderman

  - continue_https_chat(): Explicitly unset
    CSP_FLAG_CLIENT_CONNECTION_KEEP_ALIVE if
    process_encrypted_request() fails. This makes it more
    obvious that the connection will not be reused.
    Previously serve() relied on
    CSP_FLAG_SERVER_CONTENT_LENGTH_SET and CSP_FLAG_CHUNKED
    being unset. Inspired by a patch from Joshua Rogers
    (Opera).

  - decompress_iob(): Add periods to a couple of log
    messages

  - Terminate the body of the HTTP snipplets with a single
    new line instead of '\r\n'.

  - configure: Add --with-assertions option and only enable
    assertions when it is used

  - windows build: Use --with-brotli and --with-mbedtls by
    default and enable dynamic error checking.

  - gif_deanimate(): Confirm we've got an image before
    trying to write it Saves a pointless buf_copy() call.

  - OpenSSL ssl_store_cert(): Remove a superfluous space
    before the serial number.

  - Action file improvements :

  - Disable fast-redirects for .golem.de/

  - Unblock requests to adri*.

  - Block requests for trc*.taboola.com/

  - Disable fast-redirects for .linkedin.com/

  - Filter file improvements :

  - Make the second pcrs job of the img-reorder filter
    greedy again. The ungreedy version broke the img tags
    on: https://bulk.fefe.de/scalability/.

  - Privoxy-Log-Parser :

  - Highlight a few more messages.

  - Clarify the --statistics output. The shown 'Reused
    connections' are server connections so name them
    appropriately.

  - Bump version to 0.9.3.

  - Privoxy-Regression-Test :

  - Add the --check-bad-ssl option to the --help output.

  - Bump version to 0.7.3.

  - Documentation :

  - Add pushing the created tag to the release steps in the
    developer manual.

  - Clarify that 'debug 32768' should be used in addition to
    the other debug directives when reporting problems.

  - Add a 'Third-party licenses and copyrights' section to
    the user manual."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bulk.fefe.de/scalability/."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected privoxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/22");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"privoxy-3.0.32-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"privoxy-debuginfo-3.0.32-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"privoxy-debugsource-3.0.32-lp152.3.9.1") ) flag++;

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
