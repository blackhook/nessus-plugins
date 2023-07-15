#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-157.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106744);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10219", "CVE-2016-10317", "CVE-2017-11714", "CVE-2017-9216", "CVE-2017-9612", "CVE-2017-9726", "CVE-2017-9727", "CVE-2017-9739", "CVE-2017-9835");

  script_name(english:"openSUSE Security Update : ghostscript (openSUSE-2018-157)");
  script_summary(english:"Check for the openSUSE-2018-157 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript fixes several security issues :

  - CVE-2017-9835: The gs_alloc_ref_array function allowed
    remote attackers to cause a denial of service
    (heap-based buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    PostScript document (bsc#1050879).

  - CVE-2017-9216: Prevent NULL pointer dereference in the
    jbig2_huffman_get function in jbig2_huffman.c which
    allowed for DoS (bsc#1040643).

  - CVE-2016-10317: The fill_threshhold_buffer function in
    base/gxht_thresh.c allowed remote attackers to cause a
    denial of service (heap-based buffer overflow and
    application crash) or possibly have unspecified other
    impact via a crafted PostScript document (bsc#1032230).

  - CVE-2017-9612: The Ins_IP function in base/ttinterp.c
    allowed remote attackers to cause a denial of service
    (use-after-free and application crash) or possibly have
    unspecified other impact via a crafted document
    (bsc#1050891).

  - CVE-2017-9726: The Ins_MDRP function in base/ttinterp.c
    allowed remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) or
    possibly have unspecified other impact via a crafted
    document (bsc#1050889).

  - CVE-2017-9727: The gx_ttfReader__Read function in
    base/gxttfb.c allowed remote attackers to cause a denial
    of service (heap-based buffer over-read and application
    crash) or possibly have unspecified other impact via a
    crafted document (bsc#1050888).

  - CVE-2017-9739: The Ins_JMPR function in base/ttinterp.c
    allowed remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) or
    possibly have unspecified other impact via a crafted
    document (bsc#1050887).

  - CVE-2017-11714: psi/ztoken.c mishandled references to
    the scanner state structure, which allowed remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted PostScript document, related to an out-of-bounds
    read in the igc_reloc_struct_ptr function in psi/igc.c
    (bsc#1051184).

  - CVE-2016-10219: The intersect function in base/gxfill.c
    allowed remote attackers to cause a denial of service
    (divide-by-zero error and application crash) via a
    crafted file (bsc#1032138).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051184"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");
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

if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-debuginfo-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-debugsource-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-devel-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-debuginfo-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-debugsource-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-mini-devel-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-x11-9.15-14.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ghostscript-x11-debuginfo-9.15-14.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-mini / ghostscript-mini-debuginfo / etc");
}
