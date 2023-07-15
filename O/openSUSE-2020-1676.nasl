#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1676.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141513);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/21");

  script_cve_id("CVE-2020-25219", "CVE-2020-26154");

  script_name(english:"openSUSE Security Update : libproxy (openSUSE-2020-1676)");
  script_summary(english:"Check for the openSUSE-2020-1676 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libproxy fixes the following issues :

  - CVE-2020-25219: Rewrote url::recvline to be nonrecursive
    (bsc#1176410).

  - CVE-2020-26154: Fixed a buffer overflow when PAC is
    enabled (bsc#1177143).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177143"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libproxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-gnome3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-gnome3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-kde-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-networkmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-networkmanager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-webkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Net-Libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Net-Libproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libproxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libproxy-debugsource-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libproxy-devel-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libproxy-tools-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libproxy-tools-debuginfo-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libproxy1-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libproxy1-debuginfo-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-libproxy-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-libproxy-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy-plugins-debugsource-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy-sharp-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-32bit-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-32bit-debuginfo-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-config-gnome3-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-config-gnome3-debuginfo-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-config-kde-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-config-kde-debuginfo-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-networkmanager-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-networkmanager-debuginfo-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-pacrunner-webkit-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libproxy1-pacrunner-webkit-debuginfo-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"perl-Net-Libproxy-0.4.15-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"perl-Net-Libproxy-debuginfo-0.4.15-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libproxy-plugins-debugsource / libproxy-sharp / etc");
}
