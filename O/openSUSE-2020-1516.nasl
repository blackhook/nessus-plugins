#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1516.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(141069);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id(
    "CVE-2019-10740",
    "CVE-2020-12625",
    "CVE-2020-12640",
    "CVE-2020-12641",
    "CVE-2020-15562",
    "CVE-2020-16145"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/13");

  script_name(english:"openSUSE Security Update : roundcubemail (openSUSE-2020-1516)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for roundcubemail fixes the following issues :

roundcubemail was upgraded to 1.3.15

This is a security update to the LTS version 1.3. (boo#1175135)

  - Security: Fix cross-site scripting (XSS) via HTML
    messages with malicious svg content [CVE-2020-16145]

  - Security: Fix cross-site scripting (XSS) via HTML
    messages with malicious math content

From 1.3.14 (boo#1173792 -> CVE-2020-15562)

  - Security: Fix cross-site scripting (XSS) via HTML
    messages with malicious svg/namespace

From 1.3.13

  - Installer: Fix regression in SMTP test section (#7417)

From 1.3.12

  - Security: Better fix for CVE-2020-12641 (boo#1171148)

  - Security: Fix XSS issue in template object 'username'
    (#7406)

  - Security: Fix couple of XSS issues in Installer (#7406)

  - Security: Fix cross-site scripting (XSS) via malicious
    XML attachment

From 1.3.11 (boo#1171148 -> CVE-2020-12641 boo#1171040 ->
CVE-2020-12625 boo#1171149 -> CVE-2020-12640)

  - Enigma: Fix compatibility with Mail_Mime >= 1.10.5

  - Fix permissions on some folders created by
    bin/install-jsdeps.sh script (#6930)

  - Fix bug where inline images could have been ignored if
    Content-Id header contained redundant spaces (#6980)

  - Fix PHP Warning: Use of undefined constant LOG_EMERGE
    (#6991)

  - Fix PHP warning: 'array_merge(): Expected parameter 2 to
    be an array, null given in sendmail.inc (#7003)

  - Security: Fix XSS issue in handling of CDATA in HTML
    messages

  - Security: Fix remote code execution via crafted
    'im_convert_path' or 'im_identify_path' settings

  - Security: Fix local file inclusion (and code execution)
    via crafted 'plugins' option

  - Security: Fix CSRF bypass that could be used to log out
    an authenticated user (#7302)

From 1.3.10 (boo#1146286)

  - Managesieve: Fix so 'Create filter' option does not show
    up when Filters menu is disabled (#6723)

  - Enigma: Fix bug where revoked users/keys were not greyed
    out in key info

  - Enigma: Fix error message when trying to encrypt with a
    revoked key (#6607)

  - Enigma: Fix 'decryption oracle' bug [CVE-2019-10740]
    (#6638) 

  - Fix compatibility with kolab/net_ldap3 > 1.0.7 (#6785)

  - Fix bug where bmp images couldn't be displayed on some
    systems (#6728)

  - Fix bug in parsing vCard data using PHP 7.3 due to an
    invalid regexp (#6744)

  - Fix bug where bold/strong text was converted to
    upper-case on html-to-text conversion (6758)

  - Fix bug in rcube_utils::parse_hosts() where %t, %d, %z
    could return only tld (#6746)

  - Fix bug where Next/Prev button in mail view didn't work
    with multi-folder search result (#6793)

  - Fix bug where selection of columns on messages list
    wasn't working

  - Fix bug in converting multi-page Tiff images to Jpeg
    (#6824)

  - Fix wrong messages order after returning to a
    multi-folder search result (#6836)

  - Fix PHP 7.4 deprecation: implode() wrong parameter order
    (#6866)

  - Fix bug where it was possible to bypass the
    position:fixed CSS check in received messages (#6898)

  - Fix bug where some strict remote URIs in url() style
    were unintentionally blocked (#6899)

  - Fix bug where it was possible to bypass the CSS jail in
    HTML messages using :root pseudo-class (#6897)

  - Fix bug where it was possible to bypass href URI check
    with data:application/xhtml+xml URIs (#6896)

From 1.3.9 (boo#1115718)

  - Fix TinyMCE download location (#6694)

  - Fix bug where a message/rfc822 part without a filename
    wasn't listed on the attachments list (#6494)

  - Fix handling of empty entries in vCard import (#6564)

  - Fix bug in parsing some IMAP command responses that
    include unsolicited replies (#6577)

  - Fix PHP 7.2 compatibility in debug_logger plugin (#6586)

  - Fix so ANY record is not used for email domain
    validation, use A, MX, CNAME, AAAA instead (#6581)

  - Fix so mime_content_type check in Installer uses files
    that should always be available (i.e. from
    program/resources) (#6599)

  - Fix missing CSRF token on a link to download too-big
    message part (#6621)

  - Fix bug when aborting dragging with ESC key didn't stop
    the move action (#6623)

  - Fix bug where next row wasn't selected after deleting a
    collapsed thread (#6655)

From 1.3.8 

  - Fix PHP warnings on dummy QUOTA responses in
    Courier-IMAP 4.17.1 (#6374)

  - Fix so fallback from BINARY to BODY FETCH is used also
    on [PARSE] errors in dovecot 2.3 (#6383)

  - Enigma: Fix deleting keys with authentication subkeys
    (#6381)

  - Fix invalid regular expressions that throw warnings on
    PHP 7.3 (#6398)

  - Fix so Classic skin splitter does not escape out of
    window (#6397)

  - Fix XSS issue in handling invalid style tag content
    (#6410)

  - Fix compatibility with MySQL 8 - error on 'system' table
    use

  - Managesieve: Fix bug where show_real_foldernames setting
    wasn't respected (#6422)

  - New_user_identity: Fix %fu/%u vars substitution in user
    specific LDAP params (#6419)

  - Fix support for 'allow-from <uri>' in 'x_frame_options'
    config option (#6449)

  - Fix bug where valid content between HTML comments could
    have been skipped in some cases (#6464)

  - Fix multiple VCard field search (#6466)

  - Fix session issue on long running requests (#6470)

From 1.3.7 (boo#1115719)

  - Fix PHP Warning: Use of undefined constant IDNA_DEFAULT
    on systems without php-intl (#6244)

  - Fix bug where some parts of quota information could have
    been ignored (#6280)

  - Fix bug where some escape sequences in html styles could
    bypass security checks

  - Fix bug where some forbidden characters on Cyrus-IMAP
    were not prevented from use in folder names

  - Fix bug where only attachments with the same name would
    be ignored on zip download (#6301)

  - Fix bug where unicode contact names could have been
    broken/emptied or caused DB errors (#6299)

  - Fix bug where after 'mark all folders as read' action
    message counters were not reset (#6307)

  - Enigma: [EFAIL] Don't decrypt PGP messages with no MDC
    protection (#6289)

  - Fix bug where some HTML comments could have been
    malformed by HTML parser (#6333)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175135");
  script_set_attribute(attribute:"solution", value:
"Update the affected roundcubemail package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"roundcubemail-1.3.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"roundcubemail-1.3.15-lp152.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
