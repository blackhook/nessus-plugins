#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1280.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(140074);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-15705");
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"openSUSE Security Update : grub2 (openSUSE-2020-1280)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for grub2 fixes the following issues :

  - CVE-2020-15705: Fail kernel validation without shim
    protocol (bsc#1174421).

  - Add fibre channel device's ofpath support to
    grub-ofpathname and search hint to speed up root device
    discovery (bsc#1172745).

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174421");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-snapper-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-systemd-sleep-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-x86_64-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-x86_64-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"grub2-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-branding-upstream-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-debuginfo-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-debugsource-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-i386-efi-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-i386-pc-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-i386-xen-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-snapper-plugin-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-systemd-sleep-plugin-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-x86_64-efi-2.02-lp151.21.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"grub2-x86_64-xen-2.02-lp151.21.27.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2 / grub2-branding-upstream / grub2-debuginfo / etc");
}
