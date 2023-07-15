#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1022.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117655);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-18233", "CVE-2017-18236", "CVE-2017-18238");

  script_name(english:"openSUSE Security Update : exempi (openSUSE-2018-1022)");
  script_summary(english:"Check for the openSUSE-2018-1022 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for exempi fixes the following security issue :

  - CVE-2017-18236: The ASF_Support::ReadHeaderObject
    function allowed remote attackers to cause a denial of
    service (infinite loop) via a crafted .asf file
    (bsc#1085589)

  - CVE-2017-18233: Prevent integer overflow in the Chunk
    class that allowed remote attackers to cause a denial of
    service (infinite loop) via crafted XMP data in a .avi
    file (bsc#1085584)

  - CVE-2017-18238: The TradQT_Manager::ParseCachedBoxes
    function allowed remote attackers to cause a denial of
    service (infinite loop) via crafted XMP data in a .qt
    file (bsc#1085583)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085589"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected exempi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exempi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exempi-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exempi-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexempi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexempi3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexempi3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexempi3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libexempi3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/24");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"exempi-debugsource-2.2.2-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exempi-tools-2.2.2-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exempi-tools-debuginfo-2.2.2-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexempi-devel-2.2.2-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexempi3-2.2.2-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libexempi3-debuginfo-2.2.2-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libexempi3-32bit-2.2.2-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libexempi3-debuginfo-32bit-2.2.2-6.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exempi-debugsource / exempi-tools / exempi-tools-debuginfo / etc");
}
