#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-675.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149594);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2020-14929");

  script_name(english:"openSUSE Security Update : alpine (openSUSE-2021-675)");
  script_summary(english:"Check for the openSUSE-2021-675 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for alpine fixes the following issues :

Update to release 2.24

  - A few crash fixes

  - Implementation of XOAUTH2 for Yahoo! Mail.

Update to release 2.23.2

  - Expansion of the configuration screen for XOAUTH2 to
    include username, and tenant.

  - Alpine uses the domain in the From: header of a message
    to generate a message-id and suppresses all information
    about Alpine, version, revision, and time of generation
    of the message-id from this header.

  - Alpine does not generate Sender or X-X-Sender by default
    by enabling [X] Disable Sender as the default.

  - Alpine does not disclose User Agent by default by
    enabling [X] Suppress User Agent by default.

  - When messages are selected, pressing the ';' command to
    broaden or narrow a search, now offers the possibility
    to completely replace the search, and is almost
    equivalent to being a shortcut to 'unselect all
    messages, and select again'.

Update to release 2.23

  - Fixes boo#1173281, CVE-2020-14929: Alpine silently
    proceeds to use an insecure connection after a /tls is
    sent in certain circumstances.

  - Implementation of XOAUTH2 authentication support for
    Outlook.

  - Add support for the OAUTHBEARER authentication method in
    Gmail.

  - Support for the SASL-IR IMAP extension.

  - Alpine can pass an HTML message to an external web
    browser, by using the 'External' command in the
    ATTACHMENT INDEX screen.

Update to release 2.22

  - Support for XOAUTH2 authentication method in Gmail. 

  - NTLM authentication support with the ntlm library.

  - Added the '/tls1_3' flag for servers that support it.

  - Add the 'g' option to the select command that works in
    IMAP servers that implement the X-GM-EXT-1 capability
    (such as the one offered by Gmail).

  - Added '/auth=XYZ' to the way to define a server. This
    allows users to select the method to authenticate to an
    IMAP, SMTP or POP3 server. Examples are /auth=plain, or
    /auth=gssapi, etc.

  - When a message is of type multipart/mixed, and its first
    part is multipart/signed, Alpine will include the text
    of the original message in a reply message, instead of
    including a multipart attachment.

  - Added backward search in the index screen.

  - pico: Add -dict option to Pico, which allows users to
    choose a dictionary when spelling.

  - Drop /usr/bin/mailutil, it is not built by default
    anymore.

  - Added Quota subcommands for printing, forwarding,
    saving, etc."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173281"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected alpine packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:alpine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:alpine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:alpine-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pico");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pico-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pilot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
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

if ( rpm_check(release:"SUSE15.2", reference:"alpine-2.24-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"alpine-debuginfo-2.24-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"alpine-debugsource-2.24-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pico-5.07-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pico-debuginfo-5.07-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pilot-2.99-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pilot-debuginfo-2.99-lp152.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "alpine / alpine-debuginfo / alpine-debugsource / pico / etc");
}
