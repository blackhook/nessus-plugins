#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-809.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111571);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-9116", "CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14351", "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14354", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14357", "CVE-2018-14358", "CVE-2018-14359", "CVE-2018-14360", "CVE-2018-14361", "CVE-2018-14362", "CVE-2018-14363");

  script_name(english:"openSUSE Security Update : mutt (openSUSE-2018-809)");
  script_summary(english:"Check for the openSUSE-2018-809 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mutt fixes the following issues :

Security issues fixed :

  - bsc#1101428: Mutt 1.10.1 security release update.

  - CVE-2018-14351: Fix imap/command.c that mishandles long
    IMAP status mailbox literal count size (bsc#1101583).

  - CVE-2018-14353: Fix imap_quote_string in imap/util.c
    that has an integer underflow (bsc#1101581).

  - CVE-2018-14362: Fix pop.c that does not forbid
    characters that may have unsafe interaction with
    message-cache pathnames (bsc#1101567).

  - CVE-2018-14354: Fix arbitrary command execution from
    remote IMAP servers via backquote characters
    (bsc#1101578).

  - CVE-2018-14352: Fix imap_quote_string in imap/util.c
    that does not leave room for quote characters
    (bsc#1101582).

  - CVE-2018-14356: Fix pop.c that mishandles a zero-length
    UID (bsc#1101576).

  - CVE-2018-14355: Fix imap/util.c that mishandles '..'
    directory traversal in a mailbox name (bsc#1101577).

  - CVE-2018-14349: Fix imap/command.c that mishandles a NO
    response without a message (bsc#1101589).

  - CVE-2018-14350: Fix imap/message.c that has a
    stack-based buffer overflow for a FETCH response with
    along INTERNALDATE field (bsc#1101588).

  - CVE-2018-14363: Fix newsrc.c that does not
    properlyrestrict '/' characters that may have unsafe
    interaction with cache pathnames (bsc#1101566).

  - CVE-2018-14359: Fix buffer overflow via base64 data
    (bsc#1101570).

  - CVE-2018-14358: Fix imap/message.c that has a
    stack-based buffer overflow for a FETCH response with
    along RFC822.SIZE field (bsc#1101571).

  - CVE-2018-14360: Fix nntp_add_group in newsrc.c that has
    a stack-based buffer overflow because of incorrect
    sscanf usage (bsc#1101569).

  - CVE-2018-14357: Fix that remote IMAP servers are allowed
    to execute arbitrary commands via backquote characters
    (bsc#1101573).

  - CVE-2018-14361: Fix that nntp.c proceeds even if memory
    allocation fails for messages data (bsc#1101568).

Bug fixes :

  - mutt reports as neomutt and incorrect version
    (bsc#1094717)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101589"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mutt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mutt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mutt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mutt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mutt-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"mutt-1.10.1-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mutt-debuginfo-1.10.1-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mutt-debugsource-1.10.1-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mutt-lang-1.10.1-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mutt / mutt-debuginfo / mutt-debugsource / mutt-lang");
}
