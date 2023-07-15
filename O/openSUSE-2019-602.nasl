#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-602.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123263);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-5156", "CVE-2018-5188");

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-2019-602)");
  script_summary(english:"Check for the openSUSE-2019-602 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for seamonkey fixes the following issues :

Mozilla SeaMonkey was updated to 2.49.4 :

Now uses Gecko 52.9.1esr (boo#1098998).

Security issues fixed with MFSA 2018-16 (boo#1098998) :

  - CVE-2018-12359: Buffer overflow using computed size of
    canvas element

  - CVE-2018-12360: Use-after-free when using focus()

  - CVE-2018-12362: Integer overflow in SSSE3 scaler

  - CVE-2018-5156: Media recorder segmentation fault when
    track type is changed during capture

  - CVE-2018-12363: Use-after-free when appending DOM nodes

  - CVE-2018-12364: CSRF attacks through 307 redirects and
    NPAPI plugins

  - CVE-2018-12365: Compromised IPC child process can list
    local filenames

  - CVE-2018-12366: Invalid data handling during QCMS
    transformations

  - CVE-2018-5188: Memory safety bugs fixed in Firefox 60,
    Firefox ESR 60.1, and Firefox ESR 52.9

Localizations finally included again (boo#1062195)

Updated summary and description to more accurately reflect what
SeaMonkey is, giving less prominence to the long- discontinued Mozilla
Application Suite that many users may no longer be familiar with

Update to SeaMonkey 2.49.2

  - Gecko 52.6esr (including security relevant fixes)
    (boo#1077291)

  - fix issue in Composer

  - With some themes, the menulist- and history-dropmarker
    didn't show

  - Scrollbars didn't show the buttons

  - WebRTC has been disabled by default. It needs an add-on
    to enable it per site

  - The active title bar was not visually emphasized

Correct requires and provides handling (boo#1076907)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098998"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.0", reference:"seamonkey-2.49.4-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"seamonkey-debuginfo-2.49.4-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"seamonkey-debugsource-2.49.4-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"seamonkey-translations-common-2.49.4-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"seamonkey-translations-other-2.49.4-lp150.2.3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-debuginfo / seamonkey-debugsource / etc");
}
