#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-625.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100501);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7585", "CVE-2017-7741", "CVE-2017-7742", "CVE-2017-8361", "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8365");

  script_name(english:"openSUSE Security Update : libsndfile (openSUSE-2017-625)");
  script_summary(english:"Check for the openSUSE-2017-625 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libsndfile fixes the following issues :

  - CVE-2017-8361: Global buffer overflow in
    flac_buffer_copy. (bsc#1036946)

  - CVE-2017-8362: Invalid memory read in flac_buffer_copy.
    (bsc#1036943)

  - CVE-2017-8363: Heap-based buffer overflow in
    flac_buffer_copy. (bsc#1036945)

  - CVE-2017-7585, CVE-2017-7741, CVE-2017-7742: Stack-based
    buffer overflows via specially crafted FLAC files.
    (bsc#1033054)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038856"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsndfile packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-debugsource-1.0.25-26.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-devel-1.0.25-26.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-progs-1.0.25-26.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-progs-debuginfo-1.0.25-26.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-progs-debugsource-1.0.25-26.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile1-1.0.25-26.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile1-debuginfo-1.0.25-26.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsndfile1-32bit-1.0.25-26.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsndfile1-debuginfo-32bit-1.0.25-26.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsndfile-progs / libsndfile-progs-debuginfo / etc");
}
