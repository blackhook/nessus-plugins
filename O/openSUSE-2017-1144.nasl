#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1144.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103798);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7793", "CVE-2017-7805", "CVE-2017-7810", "CVE-2017-7814", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7823", "CVE-2017-7824", "CVE-2017-7825");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2017-1144)");
  script_summary(english:"Check for the openSUSE-2017-1144 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to 52.4.0 (boo#1060445)

  - new behavior was introduced for replies to mailing list
    posts: 'When replying to a mailing list, reply will be
    sent to address in From header ignoring Reply-to
    header'. A new preference mail.override_list_reply_to
    allows to restore the previous behavior.

  - Under certain circumstances (image attachment and
    non-image attachment), attached images were shown
    truncated in messages stored in IMAP folders not
    synchronised for offline use.

  - IMAP UIDs > 0x7FFFFFFF now handled properly Security
    fixes from Gecko 52.4esr

  - CVE-2017-7793 (bmo#1371889) Use-after-free with Fetch
    API

  - CVE-2017-7818 (bmo#1363723) Use-after-free during ARIA
    array manipulation

  - CVE-2017-7819 (bmo#1380292) Use-after-free while
    resizing images in design mode

  - CVE-2017-7824 (bmo#1398381) Buffer overflow when drawing
    and validating elements with ANGLE

  - CVE-2017-7805 (bmo#1377618) (fixed via NSS requirement)
    Use-after-free in TLS 1.2 generating handshake hashes

  - CVE-2017-7814 (bmo#1376036) Blob and data URLs bypass
    phishing and malware protection warnings

  - CVE-2017-7825 (bmo#1393624, bmo#1390980) (OSX-only) OS X
    fonts render some Tibetan and Arabic unicode characters
    as spaces

  - CVE-2017-7823 (bmo#1396320) CSP sandbox directive did
    not create a unique origin

  - CVE-2017-7810 Memory safety bugs fixed in Firefox 56 and
    Firefox ESR 52.4

  - Add alsa-devel BuildRequires: we care for ALSA support
    to be built and thus need to ensure we get the
    dependencies in place. In the past, alsa-devel was
    pulled in by accident: we buildrequire libgnome-devel.
    This required esound-devel and that in turn pulled in
    alsa-devel for us. libgnome is being fixed to no longer
    require esound-devel."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060445"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");
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

if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-52.4.0-41.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-buildsymbols-52.4.0-41.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debuginfo-52.4.0-41.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debugsource-52.4.0-41.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-devel-52.4.0-41.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-common-52.4.0-41.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-other-52.4.0-41.18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-52.4.0-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-buildsymbols-52.4.0-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debuginfo-52.4.0-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debugsource-52.4.0-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-devel-52.4.0-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-common-52.4.0-47.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-other-52.4.0-47.1") ) flag++;

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
