#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1779.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126909);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2017-12481", "CVE-2017-12482", "CVE-2017-2807", "CVE-2017-2808");

  script_name(english:"openSUSE Security Update : ledger (openSUSE-2019-1779)");
  script_summary(english:"Check for the openSUSE-2019-1779 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ledger fixes the following issues :

ledger was updated to 3.1.3 :

  + Properly reject postings with a comment right after the
    flag (bug #1753)

  + Make sorting order of lot information deterministic (bug
    #1747)

  + Fix bug in tag value parsing (bug #1702)

  + Remove the org command, which was always a hack to begin
    with (bug #1706)

  + Provide Docker information in README

  + Various small documentation improvements 

This also includes the update to 3.1.2 :

  + Increase maximum length for regex from 255 to 4095 (bug
    #981)

  + Initialize periods from from/since clause rather than
    earliest transaction date (bug #1159)

  + Check balance assertions against the amount after the
    posting (bug #1147)

  + Allow balance assertions with multiple posts to same
    account (bug #1187)

  + Fix period duration of 'every X days' and similar
    statements (bug #370)

  + Make option --force-color not require --color anymore
    (bug #1109)

  + Add quoted_rfc4180 to allow CVS output with RFC 4180
    compliant quoting.

  + Add support for --prepend-format in accounts command

  + Fix handling of edge cases in trim function (bug #520)

  + Fix auto xact posts not getting applied to account total
    during journal parse (bug #552)

  + Transfer null_post flags to generated postings

  + Fix segfault when using --market with --group-by

  + Use amount_width variable for budget report

  + Keep pending items in budgets until the last day they
    apply

  + Fix bug where .total used in value expressions breaks
    totals

  + Make automated transactions work with assertions (bug
    #1127)

  + Improve parsing of date tokens (bug #1626)

  + Don't attempt to invert a value if it's already zero
    (bug #1703)

  + Do not parse user-specified init-file twice

  + Fix parsing issue of effective dates (bug #1722,
    TALOS-2017-0303, CVE-2017-2807)

  + Fix use-after-free issue with deferred postings (bug
    #1723, TALOS-2017-0304, CVE-2017-2808)

  + Fix possible stack overflow in option parsing routine
    (bug #1222, CVE-2017-12481)

  + Fix possible stack overflow in date parsing routine (bug
    #1224, CVE-2017-12482)

  + Fix use-after-free when using --gain (bug #541)

  + Python: Removed double quotes from Unicode values.

  + Python: Ensure that parse errors produce useful
    RuntimeErrors

  + Python: Expose journal expand_aliases

  + Python: Expose journal_t::register_account

  + Improve bash completion

  + Emacs Lisp files have been moved to
    https://github.com/ledger/ledger-mode

  + Various documentation improvements"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ledger/ledger-mode"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ledger packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ledger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ledger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ledger-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ledger-3.1.3-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ledger-debuginfo-3.1.3-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ledger-debugsource-3.1.3-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ledger / ledger-debuginfo / ledger-debugsource");
}
