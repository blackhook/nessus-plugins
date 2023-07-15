#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-443.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109716);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-17973", "CVE-2017-9935", "CVE-2018-5784");

  script_name(english:"openSUSE Security Update : tiff (openSUSE-2018-443)");
  script_summary(english:"Check for the openSUSE-2018-443 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following issues :

  - CVE-2017-9935: There was a heap-based buffer overflow in
    the t2p_write_pdf function in tools/tiff2pdf.c. This
    heap overflow could lead to different damages. For
    example, a crafted TIFF document can lead to an
    out-of-bounds read in TIFFCleanup, an invalid free in
    TIFFClose or t2p_free, memory corruption in
    t2p_readwrite_pdf_image, or a double free in t2p_free.
    Given these possibilities, it probably could cause
    arbitrary code execution (bsc#1046077)

  - CVE-2017-17973: There is a heap-based use-after-free in
    the t2p_writeproc function in tiff2pdf.c. (bsc#1074318)

  - CVE-2018-5784: There is an uncontrolled resource
    consumption in the TIFFSetDirectory function of
    tif_dir.c. Remote attackers could leverage this
    vulnerability to cause a denial of service via a crafted
    tif file. This occurs because the declared number of
    directory entries is not validated against the actual
    number of directory entries (bsc#1081690)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081690"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");
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

if ( rpm_check(release:"SUSE42.3", reference:"libtiff-devel-4.0.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtiff5-4.0.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtiff5-debuginfo-4.0.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-4.0.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-debuginfo-4.0.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-debugsource-4.0.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff5-32bit-4.0.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.9-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-devel-32bit / libtiff-devel / libtiff5-32bit / libtiff5 / etc");
}
