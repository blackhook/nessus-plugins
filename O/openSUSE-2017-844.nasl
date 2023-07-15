#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-844.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101972);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-9262", "CVE-2016-9388", "CVE-2016-9389", "CVE-2016-9390", "CVE-2016-9391", "CVE-2016-9392", "CVE-2016-9393", "CVE-2016-9394", "CVE-2017-1000050");

  script_name(english:"openSUSE Security Update : jasper (openSUSE-2017-844)");
  script_summary(english:"Check for the openSUSE-2017-844 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for jasper fixes the following issues :

Security issues fixed :

  - CVE-2016-9262: Multiple integer overflows in the
    jas_realloc function in base/jas_malloc.c and mem_resize
    function in base/jas_stream.c allow remote attackers to
    cause a denial of service via a crafted image, which
    triggers use after free vulnerabilities. (bsc#1009994)

  - CVE-2016-9388: The ras_getcmap function in ras_dec.c
    allows remote attackers to cause a denial of service
    (assertion failure) via a crafted image file.
    (bsc#1010975)

  - CVE-2016-9389: The jpc_irct and jpc_iict functions in
    jpc_mct.c allow remote attackers to cause a denial of
    service (assertion failure). (bsc#1010968)

  - CVE-2016-9390: The jas_seq2d_create function in
    jas_seq.c allows remote attackers to cause a denial of
    service (assertion failure) via a crafted image file.
    (bsc#1010774)

  - CVE-2016-9391: The jpc_bitstream_getbits function in
    jpc_bs.c allows remote attackers to cause a denial of
    service (assertion failure) via a very large integer.
    (bsc#1010782)

  - CVE-2017-1000050: The jp2_encode function in jp2_enc.c
    allows remote attackers to cause a denial of service.
    (bsc#1047958)

CVEs already fixed with previous update :

  - CVE-2016-9392: The calcstepsizes function in jpc_dec.c
    allows remote attackers to cause a denial of service
    (assertion failure) via a crafted file. (bsc#1010757)

  - CVE-2016-9393: The jpc_pi_nextrpcl function in
    jpc_t2cod.c allows remote attackers to cause a denial of
    service (assertion failure) via a crafted file.
    (bsc#1010766)

  - CVE-2016-9394: The jas_seq2d_create function in
    jas_seq.c allows remote attackers to cause a denial of
    service (assertion failure) via a crafted file.
    (bsc#1010756)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047958"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jasper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/26");
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

if ( rpm_check(release:"SUSE42.2", reference:"jasper-1.900.14-175.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"jasper-debuginfo-1.900.14-175.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"jasper-debugsource-1.900.14-175.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper-devel-1.900.14-175.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper1-1.900.14-175.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libjasper1-debuginfo-1.900.14-175.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-175.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-175.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"jasper-1.900.14-179.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"jasper-debuginfo-1.900.14-179.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"jasper-debugsource-1.900.14-179.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjasper-devel-1.900.14-179.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjasper1-1.900.14-179.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjasper1-debuginfo-1.900.14-179.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-179.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-179.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-debuginfo / jasper-debugsource / libjasper-devel / etc");
}
