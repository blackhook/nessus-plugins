#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-719.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75150);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-1718", "CVE-2013-1719", "CVE-2013-1720", "CVE-2013-1722", "CVE-2013-1723", "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1728", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737", "CVE-2013-1738");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-SU-2013:1495-1)");
  script_summary(english:"Check for the openSUSE-2013-719 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This MozillaThunderbird update to version 24.0 fixes several security
and non-security issues :

  - update to Thunderbird 24.0 (bnc#840485)

  - MFSA 2013-76/CVE-2013-1718/CVE-2013-1719 Miscellaneous
    memory safety hazards

  - MFSA 2013-77/CVE-2013-1720 (bmo#888820) Improper state
    in HTML5 Tree Builder with templates

  - MFSA 2013-79/CVE-2013-1722 (bmo#893308) Use-after-free
    in Animation Manager during stylesheet cloning

  - MFSA 2013-80/CVE-2013-1723 (bmo#891292) NativeKey
    continues handling key messages after widget is
    destroyed

  - MFSA 2013-81/CVE-2013-1724 (bmo#894137) Use-after-free
    with select element

  - MFSA 2013-82/CVE-2013-1725 (bmo#876762) Calling scope
    for new JavaScript objects can lead to memory corruption

  - MFSA 2013-85/CVE-2013-1728 (bmo#883686) Uninitialized
    data in IonMonkey

  - MFSA 2013-88/CVE-2013-1730 (bmo#851353) Compartment
    mismatch re-attaching XBL-backed nodes

  - MFSA 2013-89/CVE-2013-1732 (bmo#883514) Buffer overflow
    with multi-column, lists, and floats

  - MFSA 2013-90/CVE-2013-1735/CVE-2013-1736 (bmo#898871,
    bmo#906301) Memory corruption involving scrolling

  - MFSA 2013-91/CVE-2013-1737 (bmo#907727) User-defined
    properties on DOM proxies get the wrong 'this' object

  - MFSA 2013-92/CVE-2013-1738 (bmo#887334, bmo#882897) GC
    hazard with default compartments and frame chain
    restoration

  - moved greek to common translation package

  - require NSPR 4.10 and NSS 3.15.1

  - add GStreamer build requirements for Gecko

  - added enigmail-build.patch to fix TB packaging
    (bmo#886095)

  - removed obsolete patches :

  - enigmail-old-gcc.patch

  - mozilla-gcc43-enums.patch

  - mozilla-gcc43-template_hacks.patch

  - mozilla-gcc43-templates_instantiation.patch

  - ppc-xpcshell.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-09/msg00059.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-24.0-49.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-24.0-49.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-24.0-49.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-24.0-49.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-24.0-49.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-24.0-49.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-24.0-49.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.5.2+24.0-49.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-24.0-61.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-buildsymbols-24.0-61.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debuginfo-24.0-61.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debugsource-24.0-61.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-24.0-61.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-common-24.0-61.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-other-24.0-61.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-1.5.2+24.0-61.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-debuginfo-1.5.2+24.0-61.25.2") ) flag++;

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
