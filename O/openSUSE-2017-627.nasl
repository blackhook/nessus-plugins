#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-627.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100502);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5209", "CVE-2017-5545", "CVE-2017-5834", "CVE-2017-5835", "CVE-2017-5836", "CVE-2017-6440", "CVE-2017-7982");

  script_name(english:"openSUSE Security Update : libplist (openSUSE-2017-627)");
  script_summary(english:"Check for the openSUSE-2017-627 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libplist fixes the following issues :

  - CVE-2017-5209: The base64decode function in libplist
    allowed attackers to obtain sensitive information from
    process memory or cause a denial of service (buffer
    over-read) via split encoded Apple Property List data
    (bsc#1019531).

  - CVE-2017-5545: The main function in plistutil.c in
    libimobiledevice libplist allowed attackers to obtain
    sensitive information from process memory or cause a
    denial of service (buffer over-read) via Apple Property
    List data that is too short. (bsc#1021610).

  - CVE-2017-5836: A type inconsistency in bplist.c was
    fixed. (bsc#1023807)

  - CVE-2017-5835: A memory allocation error leading to DoS
    was fixed. (bsc#1023822)

  - CVE-2017-5834: A heap-buffer overflow in parse_dict_node
    was fixed. (bsc#1023848)

  - CVE-2017-6440: Ensure that sanity checks work on 32-bit
    platforms. (bsc#1029631)

  - CVE-2017-7982: Add some safety checks, backported from
    upstream (bsc#1035312). 

  - CVE-2017-5836: A maliciously crafted file could cause
    the application to crash. (bsc#1023807).

  - CVE-2017-5835: Malicious crafted file could cause
    libplist to allocate large amounts of memory and consume
    lots of CPU (bsc#1023822) 

  - CVE-2017-5834: Maliciou crafted file could cause a heap
    buffer overflow or segmentation fault (bsc#1023848) This
    update was imported from the SUSE:SLE-12-SP2:Update
    update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035312"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libplist packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist++3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist++3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist++3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libplist3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:plistutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:plistutil-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-plist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-plist-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");
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

if ( rpm_check(release:"SUSE42.2", reference:"libplist++-devel-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libplist++3-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libplist++3-debuginfo-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libplist-debugsource-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libplist-devel-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libplist3-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libplist3-debuginfo-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"plistutil-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"plistutil-debuginfo-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-plist-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-plist-debuginfo-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libplist++3-32bit-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libplist++3-debuginfo-32bit-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libplist3-32bit-1.12-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libplist3-debuginfo-32bit-1.12-7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libplist++-devel / libplist++3 / libplist++3-32bit / etc");
}
