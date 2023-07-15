#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1149.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123778);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-18584", "CVE-2018-18585");

  script_name(english:"openSUSE Security Update : libmspack (openSUSE-2019-1149)");
  script_summary(english:"Check for the openSUSE-2019-1149 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libmspack fixes the following issues :

Security issues fixed :

  - CVE-2018-18584: The CAB block input buffer was one byte
    too small for the maximal Quantum block, leading to an
    out-of-bounds write. (bsc#1113038)

  - CVE-2018-18585: chmd_read_headers accepted a filename
    that has '\0' as its first or second character (such as
    the '/\0' name). (bsc#1113039)

  - Fix off-by-one bounds check on CHM PMGI/PMGL chunk
    numbers and reject empty filenames.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113039"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmspack packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18585");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmspack-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmspack-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmspack0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmspack0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmspack0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmspack0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mspack-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mspack-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libmspack-debugsource-0.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmspack-devel-0.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmspack0-0.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmspack0-debuginfo-0.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mspack-tools-0.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mspack-tools-debuginfo-0.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmspack0-32bit-0.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmspack0-32bit-debuginfo-0.6-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmspack-debugsource / libmspack-devel / libmspack0 / etc");
}
