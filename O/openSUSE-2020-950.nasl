#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-950.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138991);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/30");

  script_cve_id("CVE-2020-6509");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2020-950)");
  script_summary(english:"Check for the openSUSE-2020-950 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

  - Update to version 69.0.3686.49

  - CHR-7971 Update chromium on desktop-stable-83-3686 to
    83.0.4103.116 (CVE-2020-6509)

  - DNA-79195 Wrong date on history

  - DNA-86090 Crash at
    views::View::ReorderChildView(views::View*, int)

  - DNA-86122 [Mac] Some popovers have incorrectly themed
    arrow

  - DNA-86833 Add hint to tell users that tab content is now
    searched

  - DNA-86906 [Search in tabs] No matching results in your
    open tabs label not displayed for some strings not
    found.

  - DNA-86983 Allow to search from the tile

  - DNA-87029 Search in tabs dropdown should disappear when
    resizing window

  - DNA-87051 No autocompletion in the address bar for Speed
    Dials

  - DNA-87091 Do not vertically center search-in-tabs dialog

  - DNA-87113 Crash at
    content::NavigationRequest::GetRenderFrameHost()

  - DNA-87114 Double scrollbar in bookmarks popup

  - DNA-87117 Hide &ldquo;Provide additional details&rdquo;
    button when crash is discarded by Socorro

  - DNA-87122 Hide provide more information button from
    infobar when crash is discarded

  - DNA-87153 The icons cover the inscription on the BABE
    picture title

  - DNA-87203 The scroll view changes visible area
    unexpectedly

  - DNA-87243 Provide missing translations

  - DNA-87245 Extend schema and report search events

  - DNA-87261 Allow to use search and modal at the same time

  - DNA-87273 Switch to dedicated subdomain

  - Complete Opera 69.0 changelog at:
    https://blogs.opera.com/desktop/changelog-for-69/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.opera.com/desktop/changelog-for-69/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173251"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"opera-69.0.3686.49-lp152.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera");
}
