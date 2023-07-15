#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1463.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119138);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-19208");

  script_name(english:"openSUSE Security Update : libwpd (openSUSE-2018-1463)");
  script_summary(english:"Check for the openSUSE-2018-1463 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libwpd fixes the following issues :

Security issue fixed :

  - CVE-2018-19208: illegal address access inside libwpd at
    function WP6ContentListener:defineTable (bsc#1115713).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115713"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwpd-0_10-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwpd-0_10-10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwpd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/26");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libwpd-0_10-10-0.10.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwpd-0_10-10-debuginfo-0.10.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwpd-debuginfo-0.10.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwpd-debugsource-0.10.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwpd-devel-0.10.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwpd-tools-0.10.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libwpd-tools-debuginfo-0.10.2-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwpd-0_10-10 / libwpd-0_10-10-debuginfo / libwpd-debuginfo / etc");
}
