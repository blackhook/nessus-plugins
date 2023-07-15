#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-522.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148409);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/14");

  script_cve_id("CVE-2020-10759");

  script_name(english:"openSUSE Security Update : fwupd (openSUSE-2021-522)");
  script_summary(english:"Check for the openSUSE-2021-522 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for fwupd fixes the following issues :

  - Update to version 1.2.14: (bsc#1182057)

  - Add SBAT section to EFI images (bsc#1182057)

  - CVE-2020-10759: Validate that gpgme_op_verify_result()
    returned at least one signature (bsc#1172643)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182057"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected fwupd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dfu-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dfu-tool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fwupd-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfwupd2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfwupd2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Fwupd-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/09");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"dfu-tool-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"dfu-tool-debuginfo-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupd-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupd-debuginfo-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupd-debugsource-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupd-devel-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"fwupd-lang-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfwupd2-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libfwupd2-debuginfo-1.2.14-lp152.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-Fwupd-2_0-1.2.14-lp152.3.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dfu-tool / dfu-tool-debuginfo / fwupd / fwupd-debuginfo / etc");
}
