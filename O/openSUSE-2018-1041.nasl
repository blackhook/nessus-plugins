#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1041.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117689);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-0732", "CVE-2018-12115");

  script_name(english:"openSUSE Security Update : nodejs6 (openSUSE-2018-1041)");
  script_summary(english:"Check for the openSUSE-2018-1041 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs6 to version 6.14.4 fixes the following issues :

Security issues fixed :

CVE-2018-12115: Fixed an out-of-bounds (OOB) write in Buffer.write()
for UCS-2 encoding (bsc#1105019) CVE-2018-0732: Upgrade to OpenSSL
1.0.2p, fixing a client DoS due to large DH parameter (bsc#1097158)

Other issues fixed :

  - Recommend same major version npm package (bsc#1097748)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105019"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/25");
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

if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-6.14.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-debuginfo-6.14.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-debugsource-6.14.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-devel-6.14.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"npm6-6.14.4-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs6 / nodejs6-debuginfo / nodejs6-debugsource / nodejs6-devel / etc");
}
