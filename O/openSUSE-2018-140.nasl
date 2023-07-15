#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-140.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106664);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-16942", "CVE-2017-6892");

  script_name(english:"openSUSE Security Update : libsndfile (openSUSE-2018-140)");
  script_summary(english:"Check for the openSUSE-2018-140 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libsndfile fixes the following issues :

  - CVE-2017-16942: Divide-by-zero in the function
    wav_w64_read_fmt_chunk(), which may lead to Denial of
    service (bsc#1069874). 

  - CVE-2017-6892: Fixed an out-of-bounds read memory access
    in the aiff_read_chanmap() (bsc#1043978).

  - CVE-2017-14634: In libsndfile 1.0.28, a divide-by-zero
    error exists in the function double64_init() in
    double64.c, which may lead to DoS when playing a crafted
    audio file. (bsc#1059911)

  - CVE-2017-14245: An out of bounds read in the function
    d2alaw_array() in alaw.c of libsndfile 1.0.28 may lead
    to a remote DoS attack or information disclosure,
    related to mishandling of the NAN and INFINITY
    floating-point values. (bsc#1059912)

  - CVE-2017-14246: An out of bounds read in the function
    d2ulaw_array() in ulaw.c of libsndfile 1.0.28 may lead
    to a remote DoS attack or information disclosure,
    related to mishandling of the NAN and INFINITY
    floating-point values.(bsc#1059913)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069874"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libsndfile-debugsource-1.0.25-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsndfile-devel-1.0.25-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsndfile-progs-1.0.25-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsndfile-progs-debuginfo-1.0.25-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsndfile-progs-debugsource-1.0.25-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsndfile1-1.0.25-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsndfile1-debuginfo-1.0.25-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsndfile1-32bit-1.0.25-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsndfile1-debuginfo-32bit-1.0.25-31.1") ) flag++;

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
