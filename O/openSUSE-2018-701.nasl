#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-701.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110959);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12372", "CVE-2018-12373", "CVE-2018-12374", "CVE-2018-5188");

  script_name(english:"openSUSE Security Update : Mozilla Thunderbird (openSUSE-2018-701)");
  script_summary(english:"Check for the openSUSE-2018-701 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Mozilla Thunderbird to version 52.9.0 fixes multiple
issues.

Security issues fixed, inherited from the Mozilla common code base
(MFSA 2018-16, bsc#1098998) :

  - CVE-2018-12359: Buffer overflow using computed size of
    canvas element

  - CVE-2018-12360: Use-after-free when using focus()

  - CVE-2018-12362: Integer overflow in SSSE3 scaler

  - CVE-2018-12363: Use-after-free when appending DOM nodes

  - CVE-2018-12364: CSRF attacks through 307 redirects and
    NPAPI plugins

  - CVE-2018-12365: Compromised IPC child process can list
    local filenames

  - CVE-2018-12366: Invalid data handling during QCMS
    transformations

  - CVE-2018-5188: Memory safety bugs fixed in Thunderbird
    52.9.0 Security issues fixed that affect e-mail privacy
    and integrity (including EFAIL) :

  - CVE-2018-12372: S/MIME and PGP decryption oracles can be
    built with HTML emails (bsc#1100082)

  - CVE-2018-12373: S/MIME plaintext can be leaked through
    HTML reply/forward (bsc#1100079)

  - CVE-2018-12374: Using form to exfiltrate encrypted mail
    part by pressing enter in form field (bsc#1100081) The
    following options are available for added security in
    certain scenarios :

  - Option for not decrypting subordinate message parts that
    otherwise might reveal decryted content to the attacker.
    Preference mailnews.p7m_subparts_external needs to be
    set to true for added security. The following upstream
    changes are included :

  - Thunderbird will now prompt to compact IMAP folders even
    if the account is online

  - Fix various problems when forwarding messages inline
    when using 'simple' HTML view

The following tracked packaging changes are included :

  - correct requires and provides handling (boo#1076907)

  - reduce memory footprint with %ix86 at linking time via
    additional compiler flags (boo#1091376)

  - Build from upstream source archive and verify source
    signature (boo#1085780)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100082"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Thunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/09");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-52.9.0-lp150.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-buildsymbols-52.9.0-lp150.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debuginfo-52.9.0-lp150.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debugsource-52.9.0-lp150.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-devel-52.9.0-lp150.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-common-52.9.0-lp150.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-other-52.9.0-lp150.3.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-52.9.0-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-buildsymbols-52.9.0-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debuginfo-52.9.0-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debugsource-52.9.0-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-devel-52.9.0-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-common-52.9.0-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-other-52.9.0-68.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
