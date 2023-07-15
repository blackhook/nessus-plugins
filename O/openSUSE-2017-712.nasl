#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-712.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100885);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7755", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7760", "CVE-2017-7761", "CVE-2017-7764", "CVE-2017-7765", "CVE-2017-7766", "CVE-2017-7767", "CVE-2017-7768", "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778");

  script_name(english:"openSUSE Security Update : Mozilla based packages (openSUSE-2017-712)");
  script_summary(english:"Check for the openSUSE-2017-712 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Mozilla Firefox, Thunderbird, and NSS fixes the
following issues :

Mozilla Firefox was updated to 52.2esr (boo#1043960) MFSA 2017-16 :

  - CVE-2017-5472 (bmo#1365602) Use-after-free using
    destroyed node when regenerating trees

  - CVE-2017-7749 (bmo#1355039) Use-after-free during
    docshell reloading

  - CVE-2017-7750 (bmo#1356558) Use-after-free with track
    elements

  - CVE-2017-7751 (bmo#1363396) Use-after-free with content
    viewer listeners

  - CVE-2017-7752 (bmo#1359547) Use-after-free with IME
    input

  - CVE-2017-7754 (bmo#1357090) Out-of-bounds read in WebGL
    with ImageInfo object

  - CVE-2017-7755 (bmo#1361326) Privilege escalation through
    Firefox Installer with same directory DLL files (Windows
    only)

  - CVE-2017-7756 (bmo#1366595) Use-after-free and
    use-after-scope logging XHR header errors

  - CVE-2017-7757 (bmo#1356824) Use-after-free in IndexedDB

  - CVE-2017-7778, CVE-2017-7778, CVE-2017-7771,
    CVE-2017-7772, CVE-2017-7773, CVE-2017-7774,
    CVE-2017-7775, CVE-2017-7776, CVE-2017-7777
    Vulnerabilities in the Graphite 2 library

  - CVE-2017-7758 (bmo#1368490) Out-of-bounds read in Opus
    encoder

  - CVE-2017-7760 (bmo#1348645) File manipulation and
    privilege escalation via callback parameter in Mozilla
    Windows Updater and Maintenance Service (Windows only)

  - CVE-2017-7761 (bmo#1215648) File deletion and privilege
    escalation through Mozilla Maintenance Service
    helper.exe application (Windows only)

  - CVE-2017-7764 (bmo#1364283) Domain spoofing with
    combination of Canadian Syllabics and other unicode
    blocks

  - CVE-2017-7765 (bmo#1273265) Mark of the Web bypass when
    saving executable files (Windows only)

  - CVE-2017-7766 (bmo#1342742) File execution and privilege
    escalation through updater.ini, Mozilla Windows Updater,
    and Mozilla Maintenance Service (Windows only)

  - CVE-2017-7767 (bmo#1336964) Privilege escalation and
    arbitrary file overwrites through Mozilla Windows
    Updater and Mozilla Maintenance Service (Windows only)

  - CVE-2017-7768 (bmo#1336979) 32 byte arbitrary file read
    through Mozilla Maintenance Service (Windows only)

  - CVE-2017-5470 Memory safety bugs fixed in Firefox 54 and
    Firefox ESR 52.2

  - remove -fno-inline-small-functions and explicitely
    optimize with

    -O2 for openSUSE > 13.2/Leap 42 to work with gcc7
    (boo#1040105)

Mozilla NSS was updated to NSS 3.28.5

  - Implemented domain name constraints for CA: TUBITAK Kamu
    SM SSL Kok Sertifikasi - Surum 1. (bmo#1350859)

  - March 2017 batch of root CA changes (bmo#1350859)
    (version 2.14) CA certificates removed: O = Japanese
    Government, OU = ApplicationCA CN = WellsSecure Public
    Root Certificate Authority CN = TURKTRUST Elektronik
    Sertifika Hizmet H6 CN = Microsec e-Szigno Root CA
    certificates added: CN = D-TRUST Root CA 3 2013 CN =
    TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1
    java-1_8_0-openjdk was rebuild against NSS 3.28.5 to
    satisfy a runtime dependency."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043960"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla based packages packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-52.2-57.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-52.2-57.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-52.2-57.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-52.2-57.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-52.2-57.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-52.2-57.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-52.2-57.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-52.2-57.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-52.2-41.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-buildsymbols-52.2-41.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debuginfo-52.2-41.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debugsource-52.2-41.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-devel-52.2-41.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-common-52.2-41.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-other-52.2-41.9.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-src-1.8.0.131-10.10.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfreebl3-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfreebl3-debuginfo-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsoftokn3-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsoftokn3-debuginfo-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-certs-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-certs-debuginfo-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-debuginfo-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-debugsource-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-devel-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-sysinit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-sysinit-debuginfo-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-tools-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-tools-debuginfo-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.28.5-40.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.28.5-40.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
