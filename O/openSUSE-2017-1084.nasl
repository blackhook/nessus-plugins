#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1084.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103400);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-14107");

  script_name(english:"openSUSE Security Update : libzip (openSUSE-2017-1084)");
  script_summary(english:"Check for the openSUSE-2017-1084 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libzip fixes the following security issue :

  - CVE-2017-14107: The _zip_read_eocd64 function mishandled
    EOCD records, which allowed remote attackers to cause a
    denial of service (memory allocation failure in
    _zip_cdir_grow in zip_dirent.c) via a crafted ZIP
    archive (bsc#1056996).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056996"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libzip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzip2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.2", reference:"libzip-0.11.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzip-debuginfo-0.11.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzip-debugsource-0.11.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzip-devel-0.11.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzip2-0.11.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzip2-debuginfo-0.11.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libzip2-32bit-0.11.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libzip2-debuginfo-32bit-0.11.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzip-0.11.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzip-debuginfo-0.11.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzip-debugsource-0.11.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzip-devel-0.11.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzip2-0.11.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzip2-debuginfo-0.11.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libzip2-32bit-0.11.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libzip2-debuginfo-32bit-0.11.1-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzip / libzip-debuginfo / libzip-debugsource / libzip-devel / etc");
}
