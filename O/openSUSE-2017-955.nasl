#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-955.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102622);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7753", "CVE-2017-7779", "CVE-2017-7782", "CVE-2017-7784", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7787", "CVE-2017-7791", "CVE-2017-7792", "CVE-2017-7798", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7802", "CVE-2017-7803", "CVE-2017-7804", "CVE-2017-7807");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2017-955)");
  script_summary(english:"Check for the openSUSE-2017-955 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaThunderbird to version 52.3 fixes security
issues and bugs. The following vulnerabilities were fixed :

  - CVE-2017-7798: XUL injection in the style editor in
    devtools

  - CVE-2017-7800: Use-after-free in WebSockets during
    disconnection

  - CVE-2017-7801: Use-after-free with marquee during window
    resizing

  - CVE-2017-7784: Use-after-free with image observers

  - CVE-2017-7802: Use-after-free resizing image elements

  - CVE-2017-7785: Buffer overflow manipulating ARIA
    attributes in DOM

  - CVE-2017-7786: Buffer overflow while painting
    non-displayable SVG

  - CVE-2017-7753: Out-of-bounds read with cached style data
    and pseudo-elements#

  - CVE-2017-7787: Same-origin policy bypass with iframes
    through page reloads

  - CVE-2017-7807: Domain hijacking through AppCache
    fallback

  - CVE-2017-7792: Buffer overflow viewing certificates with
    an extremely long OID

  - CVE-2017-7804: Memory protection bypass through
    WindowsDllDetourPatcher

  - CVE-2017-7791: Spoofing following page navigation with
    data: protocol and modal alerts

  - CVE-2017-7782: WindowsDllDetourPatcher allocates memory
    without DEP protections

  - CVE-2017-7803: CSP containing 'sandbox' improperly
    applied

  - CVE-2017-7779: Memory safety bugs fixed in Firefox 55
    and Firefox ESR 52.3

The following bugs were fixed :

  - Unwanted inline images shown in rogue SPAM messages

  - Deleting message from the POP3 server not working when
    maildir storage was used

  - Message disposition flag (replied / forwarded) lost when
    reply or forwarded message was stored as draft and draft
    was sent later

  - Inline images not scaled to fit when printing

  - Selected text from another message sometimes included in
    a reply

  - No authorisation prompt displayed when inserting image
    into email body although image URL requires
    authentication

  - Large attachments taking a long time to open under some
    circumstances"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052829"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/21");
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

if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-52.3.0-41.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-buildsymbols-52.3.0-41.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debuginfo-52.3.0-41.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debugsource-52.3.0-41.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-devel-52.3.0-41.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-common-52.3.0-41.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-other-52.3.0-41.15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-52.3.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-buildsymbols-52.3.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debuginfo-52.3.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debugsource-52.3.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-devel-52.3.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-common-52.3.0-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-other-52.3.0-44.1") ) flag++;

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
