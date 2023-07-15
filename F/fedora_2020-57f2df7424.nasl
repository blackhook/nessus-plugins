#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-57f2df7424.
#

include("compat.inc");

if (description)
{
  script_id(136436);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/11");
  script_xref(name:"FEDORA", value:"2020-57f2df7424");

  script_name(english:"Fedora 30 : roundcubemail (2020-57f2df7424)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 1.4.4**

This is a **service and security update** to the stable version 1.4 of
Roundcube Webmail. It contains four fixes for recently reported
security vulnerabilities as well a number of general improvements from
our issue tracker. 

  - Fix bug where attachments with Content-Id were attached
    to the message on reply (#7122)

  - Fix identity selection on reply when both sender and
    recipient addresses are included in identities (#7211)

  - Elastic: Fix text selection with Shift+PageUp and
    Shift+PageDown in plain text editor when using Chrome
    (#7230)

  - Elastic: Fix recipient input bug when using click to
    select a contact from autocomplete list (#7231)

  - Elastic: Fix color of a folder with recent messages
    (#7281)

  - Elastic: Restrict logo size in print view (#7275)

  - Fix invalid Content-Type for messages with only html
    part and inline images - Mail_Mime-1.10.7 (#7261)

  - Fix missing contact display name in QR Code data (#7257)

  - Fix so button label in Select image/media dialogs is
    'Close' not 'Cancel' (#7246)

  - Fix regression in testing database schema on MSSQL
    (#7227)

  - Fix cursor position after inserting a group to a
    recipient input using autocompletion (#7267)

  - Fix string literals handling in IMAP STATUS (and various
    other) responses (#7290)

  - Fix bug where multiple images in a message were replaced
    by the first one on forward/reply/edit (#7293)

  - Fix handling keyservers configured with protocol prefix
    (#7295)

  - Markasjunk: Fix marking as spam/ham on moving messages
    with Move menu (#7189)

  - Markasjunk: Fix bug where moving to Junk was failing on
    messages selected with Select > All (#7206)

  - Fix so imap error message is displayed to the user on
    folder create/update (#7245)

  - Fix bug where a special folder couldn't be created if a
    special-use flag is not supported (#7147)

  - Mailvelope: Fix bug where recipients with name were not
    handled properly in mail compose (#7312)

  - Fix characters encoding in group rename input after
    group creation/rename (#7330)

  - Fix bug where some message/rfc822 parts could not be
    attached on forward (#7323)

  - Make install-jsdeps.sh script working without the 'file'
    program installed (#7325)

  - Fix performance issue of parsing big HTML messages by
    disabling HTML5 parser for these (#7331)

  - Fix so Print button for PDF attachments works on Firefox
    >= 75 (#5125)

  - **Security**: Fix XSS issue in handling of CDATA in HTML
    messages

  - **Security**: Fix remote code execution via crafted
    'im_convert_path' or 'im_identify_path' settings

  - **Security**: Fix local file inclusion (and code
    execution) via crafted 'plugins' option

  - **Security**: Fix CSRF bypass that could be used to log
    out an authenticated user (#7302)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-57f2df7424"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"roundcubemail-1.4.4-1.fc30")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
