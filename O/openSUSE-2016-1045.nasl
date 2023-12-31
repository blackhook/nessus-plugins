#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1045.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93335);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-8872", "CVE-2016-4804");

  script_name(english:"openSUSE Security Update : dosfstools (openSUSE-2016-1045)");
  script_summary(english:"Check for the openSUSE-2016-1045 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dosfstools was updated to fix two security issues.

These security issues were fixed :

  - CVE-2015-8872: The set_fat function in fat.c in
    dosfstools might have allowed attackers to corrupt a
    FAT12 filesystem or cause a denial of service (invalid
    memory read and crash) by writing an odd number of
    clusters to the third to last entry on a FAT12
    filesystem, which triggers an 'off-by-two error
    (bsc#980364).

  - CVE-2016-4804: The read_boot function in boot.c in
    dosfstools allowed attackers to cause a denial of
    service (crash) via a crafted filesystem, which triggers
    a heap-based buffer overflow in the (1) read_fat
    function or an out-of-bounds heap read in (2) get_fat
    function (bsc#980377).

This non-security issue was fixed :

  - bsc#912607: Attempt to rename root dir in fsck due to
    uninitialized fields. This update was imported from the
    SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980377"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dosfstools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dosfstools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dosfstools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dosfstools-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"dosfstools-3.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dosfstools-debuginfo-3.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dosfstools-debugsource-3.0.26-9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dosfstools / dosfstools-debuginfo / dosfstools-debugsource");
}
