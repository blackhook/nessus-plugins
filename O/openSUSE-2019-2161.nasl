#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2161.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129337);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-13627");

  script_name(english:"openSUSE Security Update : libgcrypt (openSUSE-2019-2161)");
  script_summary(english:"Check for the openSUSE-2019-2161 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libgcrypt fixes the following issues :

Security issues fixed :

&#9; - CVE-2019-13627: Mitigated ECDSA timing attack. (bsc#1148987)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148987"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcrypt20-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");
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

if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-cavs-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-cavs-debuginfo-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-debugsource-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-devel-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt-devel-debuginfo-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt20-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt20-debuginfo-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgcrypt20-hmac-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt-devel-32bit-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt-devel-32bit-debuginfo-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt20-32bit-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt20-32bit-debuginfo-1.8.2-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgcrypt20-hmac-32bit-1.8.2-lp150.5.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgcrypt-cavs / libgcrypt-cavs-debuginfo / libgcrypt-debugsource / etc");
}
