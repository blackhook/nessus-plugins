#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1209.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139652);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2020-15396", "CVE-2020-15397");

  script_name(english:"openSUSE Security Update : hylafax+ (openSUSE-2020-1209)");
  script_summary(english:"Check for the openSUSE-2020-1209 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for hylafax+ fixes the following issues :

Hylafax was updated to upstream version 7.0.3.

Security issues fixed :

  - CVE-2020-15396: Secure temporary directory creation for
    faxsetup, faxaddmodem, and probemodem (boo#1173521).

  - CVE-2020-15397: Sourcing of files into binaries from
    user writeable directories (boo#1173519).

Non-security issues fixed :

  - add UseSSLFax feature in sendfax, sendfax.conf,
    hyla.conf, and JobControl (31 Jul 2020)

  - be more resilient in listening for the Phase C carrier
    (30 Jul 2020)

  - make sure to return to command mode if HDLC receive
    times out (29 Jul 2020)

  - make faxmail ignore boundaries on parts other than
    multiparts (29 Jul 2020)

  - don't attempt to write zero bytes of data to a TIFF (29
    Jul 2020)

  - don't ever respond to CRP with CRP (28 Jul 2020)

  - reset frame counter when a sender retransmits PPS for a
    previously confirmed ECM block (26 Jul 2020)

  - scrutinize PPM before concluding that the sender missed
    our MCF (23 Jul 2020)

  - fix modem recovery after SSL Fax failure (22, 26 Jul
    2020)

  - ignore echo of PPR, RTN, CRP (10, 13, 21 Jul 2020)

  - attempt to handle NSF/CSI/DIS in Class 1 sending Phase D
    (6 Jul 2020)

  - run scripts directly rather than invoking them via a
    shell for security hardening (3-5 Jul 2020)

  - add senderFumblesECM feature (3 Jul 2020)

  - add support for PIN/PIP/PRI-Q/PPS-PRI-Q signals, add
    senderConfusesPIN feature, and utilize PIN for rare
    conditions where it may be helpful (2, 6, 13-14 Jul
    2020)

  - add senderConfusesRTN feature (25-26 Jun 2020)

  - add MissedPageHandling feature (24 Jun 2020)

  - use and handle CFR in Phase D to retransmit Phase C (16,
    23 Jun 2020)

  - cope with hearing echo of RR, CTC during Class 1 sending
    (15-17 Jun 2020)

  - fix listening for retransmission of MPS/EOP/EOM if it
    was received corrupt on the first attempt (15 Jun 2020)

  - don't use CRP when receiving PPS/PPM as some senders
    think we are sending MCF (12 Jun 2020)

  - add BR_SSLFAX to show SSL Fax in notify and faxinfo
    output (1 Jun 2020)

  - have faxinfo put units on non-standard page dimensions
    (28 May 2020)

  - improve error messages for JobHost connection errors (22
    May 2020)

  - fix perpetual blocking of jobs when a job preparation
    fails, attempt to fix similar blocking problems for bad
    jobs in batches, and add 'unblock' faxconfig feature (21
    May 2020)

  - ignore TCF if we're receiving an SSL Fax (31 Jan 2020)

  - fixes for build on FreeBSD 12.1 (31 Jan - 3 Feb 2020)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173521"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected hylafax+ packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfaxutil7_0_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfaxutil7_0_3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"hylafax+-7.0.3-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hylafax+-client-7.0.3-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hylafax+-client-debuginfo-7.0.3-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hylafax+-debuginfo-7.0.3-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"hylafax+-debugsource-7.0.3-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfaxutil7_0_3-7.0.3-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfaxutil7_0_3-debuginfo-7.0.3-lp152.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hylafax+ / hylafax+-client / hylafax+-client-debuginfo / etc");
}
