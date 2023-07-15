#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-538.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123227);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-0247", "CVE-2015-1572");

  script_name(english:"openSUSE Security Update : e2fsprogs (openSUSE-2019-538)");
  script_summary(english:"Check for the openSUSE-2019-538 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for e2fsprogs fixes the following issues :

Security issues fixed :

  - CVE-2015-0247: Fixed couple of heap overflows in
    e2fsprogs (fsck, dumpe2fs, e2image...) (bsc#915402).

  - CVE-2015-1572: Fixed potential buffer overflow in
    closefs() (bsc#918346).

Bug fixes :

  - bsc#1038194: generic/405 test fails with
    /dev/mapper/thin-vol is inconsistent on ext4 file
    system.

  - bsc#1009532: resize2fs hangs when trying to resize a
    large ext4 file system.

  - bsc#960273: xfsprogs does not call
    %(?regenerate_initrd_post).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=918346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960273"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected e2fsprogs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
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

if ( rpm_check(release:"SUSE15.0", reference:"e2fsprogs-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"e2fsprogs-debuginfo-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"e2fsprogs-debugsource-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"e2fsprogs-devel-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcom_err-devel-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcom_err-devel-static-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcom_err2-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcom_err2-debuginfo-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libext2fs-devel-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libext2fs-devel-static-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libext2fs2-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libext2fs2-debuginfo-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"e2fsprogs-32bit-debuginfo-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcom_err-devel-32bit-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcom_err2-32bit-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcom_err2-32bit-debuginfo-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libext2fs-devel-32bit-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libext2fs2-32bit-1.43.8-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libext2fs2-32bit-debuginfo-1.43.8-lp150.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs / e2fsprogs-32bit-debuginfo / e2fsprogs-debuginfo / etc");
}
