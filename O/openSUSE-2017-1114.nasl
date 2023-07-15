#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1114.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103621);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7793", "CVE-2017-7805", "CVE-2017-7810", "CVE-2017-7814", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7823", "CVE-2017-7824");

  script_name(english:"openSUSE Security Update : Mozilla Firefox and NSS (openSUSE-2017-1114)");
  script_summary(english:"Check for the openSUSE-2017-1114 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Mozilla Firefox 52.4esr, along with Mozilla NSS 3.28.6,
fixes security issues and bugs. The following vulnerabilities advised
upstream under MFSA 2017-22 (boo#1060445) were fixed :

  - CVE-2017-7793: Use-after-free with Fetch API

  - CVE-2017-7818: Use-after-free during ARIA array
    manipulation

  - CVE-2017-7819: Use-after-free while resizing images in
    design mode

  - CVE-2017-7824: Buffer overflow when drawing and
    validating elements with ANGLE

  - CVE-2017-7814: Blob and data URLs bypass phishing and
    malware protection warnings

  - CVE-2017-7823: CSP sandbox directive did not create a
    unique origin

  - CVE-2017-7810: Memory safety bugs fixed in Firefox 56
    and Firefox ESR 52.4 The following security issue was
    fixed in Mozilla NSS 3.28.6 :

  - CVE-2017-7805: Use-after-free in TLS 1.2 generating
    handshake hashes (bsc#1061005)

The following bug was fixed :

  - boo#1029917: language accept header use incorrect locale

For compatibility reasons, java-1_8_0-openjdk was rebuilt to the
updated version of NSS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061005"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox and NSS packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/03");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-52.4.0-57.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-52.4.0-57.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-52.4.0-57.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-52.4.0-57.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-52.4.0-57.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-52.4.0-57.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-52.4.0-57.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-52.4.0-57.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-src-1.8.0.144-10.15.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfreebl3-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfreebl3-debuginfo-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsoftokn3-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsoftokn3-debuginfo-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-certs-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-certs-debuginfo-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-debuginfo-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-debugsource-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-devel-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-sysinit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-sysinit-debuginfo-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-tools-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-tools-debuginfo-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaFirefox-52.4.0-57.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaFirefox-branding-upstream-52.4.0-57.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-52.4.0-57.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.4.0-57.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.4.0-57.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaFirefox-devel-52.4.0-57.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaFirefox-translations-common-52.4.0-57.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"MozillaFirefox-translations-other-52.4.0-57.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.28.6-40.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-52.4.0-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-branding-upstream-52.4.0-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-buildsymbols-52.4.0-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debuginfo-52.4.0-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debugsource-52.4.0-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-devel-52.4.0-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-common-52.4.0-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-other-52.4.0-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-accessibility-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-debugsource-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-demo-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-devel-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-headless-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-javadoc-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-src-1.8.0.144-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreebl3-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreebl3-debuginfo-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsoftokn3-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsoftokn3-debuginfo-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-certs-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-certs-debuginfo-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-debuginfo-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-debugsource-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-devel-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-sysinit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-sysinit-debuginfo-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-tools-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mozilla-nss-tools-debuginfo-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-52.4.0-63.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-branding-upstream-52.4.0-63.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-52.4.0-63.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.4.0-63.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.4.0-63.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-devel-52.4.0-63.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-translations-common-52.4.0-63.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaFirefox-translations-other-52.4.0-63.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.28.6-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.28.6-44.1") ) flag++;

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
