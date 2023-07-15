#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1139.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117987);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-16541", "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-12371", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12383", "CVE-2018-12385", "CVE-2018-16541", "CVE-2018-5156", "CVE-2018-5187", "CVE-2018-5188");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2018-1139)");
  script_summary(english:"Check for the openSUSE-2018-1139 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Mozilla Thunderbird to version 60.2.1 fixes multiple
issues.

Multiple security issues were fixed in the Mozilla platform as advised
in MFSA 2018-25. In general, these flaws cannot be exploited through
email in Thunderbird because scripting is disabled when reading mail,
but are potentially risks in browser or browser-like contexts :

  - CVE-2018-12377: Use-after-free in refresh driver timers
    (bsc#1107343)

  - CVE-2018-12378: Use-after-free in IndexedDB
    (bsc#1107343)

  - CVE-2017-16541: Proxy bypass using automount and autofs
    (bsc#1066489)

  - CVE-2018-12376: Memory safety bugs fixed in Firefox 62
    and Firefox ESR 60.2 (bsc#1107343)

  - CVE-2018-12385: Crash in TransportSecurityInfo due to
    cached data (bsc#1109363)

  - CVE-2018-12383: Setting a master password did not delete
    unencrypted previously stored passwords (bsc#1107343)

  - CVE-2018-12359: Buffer overflow using computed size of
    canvas element (bsc#1098998)

  - CVE-2018-12360: Use-after-free when using focus()
    (bsc#1098998)

  - CVE-2018-12361: Integer overflow in SwizzleData
    (bsc#1098998)

  - CVE-2018-12362: Integer overflow in SSSE3 scaler
    (bsc#1098998)

  - CVE-2018-12363: Use-after-free when appending DOM nodes
    (bsc#1098998)

  - CVE-2018-12364: CSRF attacks through 307 redirects and
    NPAPI plugins (bsc#1098998)

  - CVE-2018-12365: Compromised IPC child process can list
    local filenames (bsc#1098998)

  - CVE-2018-12371: Integer overflow in Skia library during
    edge builder allocation (bsc#1098998)

  - CVE-2018-12366: Invalid data handling during QCMS
    transformations (bsc#1098998)

  - CVE-2018-12367: Timing attack mitigation of
    PerformanceNavigationTiming (bsc#1098998)

  - CVE-2018-5156: Media recorder segmentation fault when
    track type is changed during capture (bsc#1098998)

  - CVE-2018-5187: Memory safety bugs fixed in Firefox 61,
    Firefox ESR 60.1, and Thunderbird 60 (bsc#1098998)

  - CVE-2018-5188: Memory safety bugs fixed in Firefox 61,
    Firefox ESR 60.1, Firefox ESR 52.9, and Thunderbird 60
    (bsc#1098998)

Other bugs fixes :

  - Fix date display issues (bsc#1109379)

  - Fix start-up crash due to folder name with special
    characters (bsc#1107772)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109379"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");
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

if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-60.2.1-lp150.3.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-buildsymbols-60.2.1-lp150.3.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debuginfo-60.2.1-lp150.3.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debugsource-60.2.1-lp150.3.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-common-60.2.1-lp150.3.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-other-60.2.1-lp150.3.19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-60.2.1-77.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-buildsymbols-60.2.1-77.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debuginfo-60.2.1-77.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debugsource-60.2.1-77.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-common-60.2.1-77.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-other-60.2.1-77.2") ) flag++;

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
