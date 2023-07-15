#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-677.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110802);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-3632", "CVE-2016-8331", "CVE-2017-11613", "CVE-2017-13726", "CVE-2017-18013", "CVE-2018-10963", "CVE-2018-7456", "CVE-2018-8905");

  script_name(english:"openSUSE Security Update : tiff (openSUSE-2018-677)");
  script_summary(english:"Check for the openSUSE-2018-677 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following issues :

These security issues were fixed :

  - CVE-2017-18013: There was a NULL pointer Dereference in
    the tif_print.c TIFFPrintDirectory function, as
    demonstrated by a tiffinfo crash. (bsc#1074317)

  - CVE-2018-10963: The TIFFWriteDirectorySec() function in
    tif_dirwrite.c allowed remote attackers to cause a
    denial of service (assertion failure and application
    crash) via a crafted file, a different vulnerability
    than CVE-2017-13726. (bsc#1092949)

  - CVE-2018-7456: Prevent a NULL pointer dereference in the
    function TIFFPrintDirectory when using the tiffinfo tool
    to print crafted TIFF information, a different
    vulnerability than CVE-2017-18013 (bsc#1082825)

  - CVE-2017-11613: Prevent denial of service in the
    TIFFOpen function. During the TIFFOpen process,
    td_imagelength is not checked. The value of
    td_imagelength can be directly controlled by an input
    file. In the ChopUpSingleUncompressedStrip function, the
    _TIFFCheckMalloc function is called based on
    td_imagelength. If the value of td_imagelength is set
    close to the amount of system memory, it will hang the
    system or trigger the OOM killer (bsc#1082332)

  - CVE-2018-8905: Prevent heap-based buffer overflow in the
    function LZWDecodeCompat via a crafted TIFF file
    (bsc#1086408)

  - CVE-2016-8331: Prevent remote code execution because of
    incorrect handling of TIFF images. A crafted TIFF
    document could have lead to a type confusion
    vulnerability resulting in remote code execution. This
    vulnerability could have been be triggered via a TIFF
    file delivered to the application using LibTIFF's tag
    extension functionality (bsc#1007276)

  - CVE-2016-3632: The _TIFFVGetField function allowed
    remote attackers to cause a denial of service
    (out-of-bounds write) or execute arbitrary code via a
    crafted TIFF image (bsc#974621)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974621"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");
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

if ( rpm_check(release:"SUSE42.3", reference:"libtiff-devel-4.0.9-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtiff5-4.0.9-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtiff5-debuginfo-4.0.9-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-4.0.9-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-debuginfo-4.0.9-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tiff-debugsource-4.0.9-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.9-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff5-32bit-4.0.9-31.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.9-31.1") ) flag++;

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
