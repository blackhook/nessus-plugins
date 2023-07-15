#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2240.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(144312);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/18");

  script_cve_id("CVE-2020-14145");

  script_name(english:"openSUSE Security Update : openssh (openSUSE-2020-2240)");
  script_summary(english:"Check for the openSUSE-2020-2240 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openssh fixes the following issues :

  - CVE-2020-14145: Fixed a potential information leak
    during host key exchange (bsc#1173513).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173513"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-askpass-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-askpass-gnome-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-helpers-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"openssh-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openssh-cavs-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openssh-cavs-debuginfo-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openssh-debuginfo-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openssh-debugsource-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openssh-fips-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openssh-helpers-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openssh-helpers-debuginfo-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"openssh-askpass-gnome-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"openssh-askpass-gnome-debuginfo-8.1p1-lp152.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"openssh-askpass-gnome-debugsource-8.1p1-lp152.4.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh-askpass-gnome / openssh-askpass-gnome-debuginfo / etc");
}
