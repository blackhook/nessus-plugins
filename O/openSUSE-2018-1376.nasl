#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1376.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118874);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-0358");

  script_name(english:"openSUSE Security Update : ntfs-3g_ntfsprogs (openSUSE-2018-1376)");
  script_summary(english:"Check for the openSUSE-2018-1376 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ntfs-3g_ntfsprogs fixes the following issues :

  - CVE-2017-0358: Missing sanitization of the environment
    during a call to modprobe allowed local users to
    escalate fo root privilege (bsc#1022500)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022500"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ntfs-3g_ntfsprogs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Debian/Ubuntu ntfs-3g Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libntfs-3g-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libntfs-3g84");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libntfs-3g84-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfs-3g-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfs-3g_ntfsprogs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ntfsprogs-debuginfo");
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

if ( rpm_check(release:"SUSE42.3", reference:"libntfs-3g-devel-2013.1.13-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libntfs-3g84-2013.1.13-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libntfs-3g84-debuginfo-2013.1.13-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfs-3g-2013.1.13-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfs-3g-debuginfo-2013.1.13-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfs-3g_ntfsprogs-debugsource-2013.1.13-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfsprogs-2013.1.13-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ntfsprogs-debuginfo-2013.1.13-7.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libntfs-3g-devel / libntfs-3g84 / libntfs-3g84-debuginfo / ntfs-3g / etc");
}
