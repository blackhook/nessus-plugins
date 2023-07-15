#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-743.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101136);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9526");

  script_name(english:"openSUSE Security Update : libgcrypt (openSUSE-2017-743)");
  script_summary(english:"Check for the openSUSE-2017-743 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libgcrypt fixes the following issues :

  - CVE-2017-9526: Store the session key in secure memory to
    ensure that constant time point operations are used in
    the MPI library. (bsc#1042326)

  - Don't require secure memory for the fips selftests, this
    prevents the 'Oops, secure memory pool already
    initialized' warning. (bsc#931932)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931932"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libgcrypt-cavs-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcrypt-cavs-debuginfo-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcrypt-debugsource-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcrypt-devel-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcrypt-devel-debuginfo-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcrypt20-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcrypt20-debuginfo-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgcrypt20-hmac-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcrypt-devel-debuginfo-32bit-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcrypt20-32bit-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcrypt20-debuginfo-32bit-1.6.1-34.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgcrypt20-hmac-32bit-1.6.1-34.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt-cavs / libgcrypt-cavs-debuginfo / libgcrypt-debugsource / etc");
}
