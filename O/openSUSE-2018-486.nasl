#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-486.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109935);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5159", "CVE-2018-5161", "CVE-2018-5162", "CVE-2018-5168", "CVE-2018-5170", "CVE-2018-5174", "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5184", "CVE-2018-5185");

  script_name(english:"openSUSE Security Update : Mozilla Thunderbird (openSUSE-2018-486)");
  script_summary(english:"Check for the openSUSE-2018-486 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Mozilla Thunderbird to version 52.8 fixes the
following issues :

Security issues fixed (MFSA 2018-13, boo#1092548) :

  - CVE-2018-5183: Backport critical security fixes in Skia

  - CVE-2018-5154: Use-after-free with SVG animations and
    clip paths

  - CVE-2018-5155: Use-after-free with SVG animations and
    text paths

  - CVE-2018-5159: Integer overflow and out-of-bounds write
    in Skia

  - CVE-2018-5168: Lightweight themes can be installed
    without user interaction

  - CVE-2018-5178: Buffer overflow during UTF-8 to Unicode
    string conversion through legacy extension

  - CVE-2018-5150: Memory safety bugs fixed in Firefox 60,
    Firefox ESR 52.8, and Thunderbird 52.8

  - CVE-2018-5161: Hang via malformed headers (bsc#1093970)

  - CVE-2018-5162: Encrypted mail leaks plaintext through
    src attribute (bsc#1093971)

  - CVE-2018-5170: Filename spoofing for external
    attachments (bsc#1093972)

  - CVE-2018-5184: Full plaintext recovery in S/MIME via
    chosen-ciphertext attack (bsc#1093969)

  - CVE-2018-5185: Leaking plaintext through HTML forms
    (bsc#1093973)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093152"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Thunderbird packages."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/21");
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

if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-52.8-lp150.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-buildsymbols-52.8-lp150.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debuginfo-52.8-lp150.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debugsource-52.8-lp150.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-devel-52.8-lp150.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-common-52.8-lp150.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-other-52.8-lp150.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-52.8-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-buildsymbols-52.8-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debuginfo-52.8-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debugsource-52.8-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-devel-52.8-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-common-52.8-63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-other-52.8-63.1") ) flag++;

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
