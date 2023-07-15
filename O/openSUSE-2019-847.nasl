#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-847.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123354);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9935", "CVE-2018-10779", "CVE-2018-15209", "CVE-2018-16335", "CVE-2018-17100", "CVE-2018-17101", "CVE-2018-17795");

  script_name(english:"openSUSE Security Update : tiff (openSUSE-2019-847)");
  script_summary(english:"Check for the openSUSE-2019-847 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following issues :

Security issue fixed :

  - CVE-2018-10779: TIFFWriteScanline in tif_write.c had a
    heap-based buffer over-read, as demonstrated by
    bmp2tiff.(bsc#1092480)

  - CVE-2018-17100: There is a int32 overflow in multiply_ms
    in tools/ppm2tiff.c, which can cause a denial of service
    (crash) or possibly have unspecified other impact via a
    crafted image file. (bsc#1108637)

  - CVE-2018-17101: There are two out-of-bounds writes in
    cpTags in tools/tiff2bw.c and tools/pal2rgb.c, which can
    cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    image file. (bsc#1108627)

  - CVE-2018-17795: The function t2p_write_pdf in tiff2pdf.c
    allowed remote attackers to cause a denial of service
    (heap-based buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    TIFF file, a similar issue to CVE-2017-9935.
    (bsc#1110358)

  - CVE-2018-16335: newoffsets handling in
    ChopUpSingleUncompressedStrip in tif_dirread.c allowed
    remote attackers to cause a denial of service
    (heap-based buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    TIFF file, as demonstrated by tiff2pdf. This is a
    different vulnerability than CVE-2018-15209.
    (bsc#1106853)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110358"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/26");
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

if ( rpm_check(release:"SUSE15.0", reference:"libtiff-devel-4.0.9-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libtiff5-4.0.9-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libtiff5-debuginfo-4.0.9-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tiff-4.0.9-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tiff-debuginfo-4.0.9-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tiff-debugsource-4.0.9-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.9-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libtiff5-32bit-4.0.9-lp150.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libtiff5-32bit-debuginfo-4.0.9-lp150.4.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-devel-32bit / libtiff-devel / libtiff5-32bit / etc");
}
