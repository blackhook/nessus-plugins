#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-759.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149887);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-32490",
    "CVE-2021-32491",
    "CVE-2021-32492",
    "CVE-2021-32493"
  );

  script_name(english:"openSUSE Security Update : djvulibre (openSUSE-2021-759)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for djvulibre fixes the following issues :

  - CVE-2021-32490 [bsc#1185895]: Out of bounds write in
    function DJVU:filter_bv() via crafted djvu file

  - CVE-2021-32491 [bsc#1185900]: Integer overflow in
    function render() in tools/ddjvu via crafted djvu file

  - CVE-2021-32492 [bsc#1185904]: Out of bounds read in
    function DJVU:DataPool:has_data() via crafted djvu file

  - CVE-2021-32493 [bsc#1185905]: Heap buffer overflow in
    function DJVU:GBitmap:decode() via crafted djvu file

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185905");
  script_set_attribute(attribute:"solution", value:
"Update the affected djvulibre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:djvulibre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:djvulibre-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:djvulibre-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdjvulibre-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdjvulibre21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdjvulibre21-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"djvulibre-3.5.27-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"djvulibre-debuginfo-3.5.27-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"djvulibre-debugsource-3.5.27-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdjvulibre-devel-3.5.27-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdjvulibre21-3.5.27-lp152.7.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdjvulibre21-debuginfo-3.5.27-lp152.7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "djvulibre / djvulibre-debuginfo / djvulibre-debugsource / etc");
}
