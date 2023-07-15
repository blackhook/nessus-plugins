#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1366.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118872);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10209", "CVE-2016-10349", "CVE-2016-10350", "CVE-2017-14166", "CVE-2017-14501", "CVE-2017-14502", "CVE-2017-14503");

  script_name(english:"openSUSE Security Update : libarchive (openSUSE-2018-1366)");
  script_summary(english:"Check for the openSUSE-2018-1366 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libarchive fixes the following issues :

  - CVE-2016-10209: The archive_wstring_append_from_mbs
    function in archive_string.c allowed remote attackers to
    cause a denial of service (NULL pointer dereference and
    application crash) via a crafted archive file.
    (bsc#1032089)

  - CVE-2016-10349: The archive_le32dec function in
    archive_endian.h allowed remote attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) via a crafted file. (bsc#1037008)

  - CVE-2016-10350: The archive_read_format_cab_read_header
    function in archive_read_support_format_cab.c allowed
    remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via
    a crafted file. (bsc#1037009)

  - CVE-2017-14166: libarchive allowed remote attackers to
    cause a denial of service (xml_data heap-based buffer
    over-read and application crash) via a crafted xar
    archive, related to the mishandling of empty strings in
    the atol8 function in archive_read_support_format_xar.c.
    (bsc#1057514)

  - CVE-2017-14501: An out-of-bounds read flaw existed in
    parse_file_info in archive_read_support_format_iso9660.c
    when extracting a specially crafted iso9660 iso file,
    related to archive_read_format_iso9660_read_header.
    (bsc#1059139)

  - CVE-2017-14502: read_header in
    archive_read_support_format_rar.c suffered from an
    off-by-one error for UTF-16 names in RAR archives,
    leading to an out-of-bounds read in
    archive_read_format_rar_read_header. (bsc#1059134)

  - CVE-2017-14503: libarchive suffered from an
    out-of-bounds read within lha_read_data_none() in
    archive_read_support_format_lha.c when extracting a
    specially crafted lha archive, related to lha_crc16.
    (bsc#1059100)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059139"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libarchive packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsdtar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/10");
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

if ( rpm_check(release:"SUSE42.3", reference:"bsdtar-3.1.2-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bsdtar-debuginfo-3.1.2-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libarchive-debugsource-3.1.2-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libarchive-devel-3.1.2-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libarchive13-3.1.2-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libarchive13-debuginfo-3.1.2-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libarchive13-32bit-3.1.2-20.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libarchive13-debuginfo-32bit-3.1.2-20.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsdtar / bsdtar-debuginfo / libarchive-debugsource / etc");
}
