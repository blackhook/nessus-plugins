#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-462.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148045);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/26");

  script_cve_id("CVE-2020-14372", "CVE-2020-25632", "CVE-2020-25647", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");

  script_name(english:"openSUSE Security Update : grub2 (openSUSE-2021-462)");
  script_summary(english:"Check for the openSUSE-2021-462 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for grub2 fixes the following issues :

grub2 implements the new 'SBAT' method for SHIM based secure boot
revocation. (bsc#1182057)

  - CVE-2020-25632: Fixed a use-after-free in rmmod command
    (bsc#1176711)

  - CVE-2020-25647: Fixed an out-of-bound write in
    grub_usb_device_initialize() (bsc#1177883)

  - CVE-2020-27749: Fixed a stack-based buffer overflow in
    grub_parser_split_cmdline (bsc#1179264)

  - CVE-2020-27779, CVE-2020-14372: Disallow cutmem and acpi
    commands in secure boot mode (bsc#1179265 bsc#1175970)

  - CVE-2021-20225: Fixed a heap out-of-bounds write in
    short form option parser (bsc#1182262)

  - CVE-2021-20233: Fixed a heap out-of-bound write due to
    mis-calculation of space required for quoting
    (bsc#1182263)

  - Fixed chainloading windows on dual boot machine
    (bsc#1183073)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183073"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected grub2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-efi-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-pc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-snapper-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-systemd-sleep-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-x86_64-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-x86_64-efi-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-x86_64-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"grub2-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-branding-upstream-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-debuginfo-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-debugsource-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-i386-efi-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-i386-efi-debug-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-i386-pc-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-i386-pc-debug-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-i386-xen-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-snapper-plugin-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-systemd-sleep-plugin-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-x86_64-efi-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-x86_64-efi-debug-2.04-lp152.7.22.7") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"grub2-x86_64-xen-2.04-lp152.7.22.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2 / grub2-branding-upstream / grub2-debuginfo / etc");
}
