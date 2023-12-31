#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update e2fsprogs-4739.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29243);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-5497");

  script_name(english:"openSUSE 10 Security Update : e2fsprogs (e2fsprogs-4739)");
  script_summary(english:"Check for the e2fsprogs-4739 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of e2fsprogs fixes several integer overflows in memory
allocating code. Programs that use libext2fs are therefore vulnerable
to memory corruptions that can lead to arbitrary code execution while
loading a specially crafted image. (CVE-2007-5497)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected e2fsprogs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:e2fsprogs-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcom_err2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libext2fs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"e2fsprogs-1.38-25.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"e2fsprogs-devel-1.38-25.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"libcom_err-1.38-25.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"e2fsprogs-32bit-1.38-25.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"e2fsprogs-devel-32bit-1.38-25.27") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"libcom_err-32bit-1.38-25.27") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"e2fsprogs-1.39-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"e2fsprogs-devel-1.39-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libcom_err-1.39-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"e2fsprogs-32bit-1.39-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"e2fsprogs-devel-32bit-1.39-23") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"libcom_err-32bit-1.39-23") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"e2fsprogs-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"e2fsprogs-devel-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libblkid-devel-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libblkid1-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libcom_err-devel-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libcom_err2-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libext2fs-devel-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libext2fs2-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libuuid-devel-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libuuid1-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libcom_err2-32bit-1.40.2-20.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libuuid1-32bit-1.40.2-20.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs");
}
