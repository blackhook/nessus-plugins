#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-314.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134348);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2019-14553", "CVE-2019-14559", "CVE-2019-14563", "CVE-2019-14575");

  script_name(english:"openSUSE Security Update : ovmf (openSUSE-2020-314)");
  script_summary(english:"Check for the openSUSE-2020-314 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ovmf fixes the following issues :

Security issues fixed :

  - CVE-2019-14563: Fixed a memory corruption caused by
    insufficient numeric truncation (bsc#1163959).

  - CVE-2019-14553: Fixed the TLS certification verification
    in HTTPS-over-IPv6 boot sequences (bsc#1153072).

  - CVE-2019-14559: Fixed a remotely exploitable memory leak
    in the ARP handling code (bsc#1163927).

  - CVE-2019-14575: Fixed an insufficient signature check in
    the DxeImageVerificationHandler (bsc#1163969).

  - Enabled HTTPS-over-IPv6 (bsc#1153072).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163969"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ovmf packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14575");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovmf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ovmf-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ovmf-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ovmf-x86_64-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"ovmf-2017+git1510945757.b2662641d5-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ovmf-tools-2017+git1510945757.b2662641d5-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"qemu-ovmf-ia32-2017+git1510945757.b2662641d5-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"qemu-ovmf-x86_64-2017+git1510945757.b2662641d5-lp151.11.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"qemu-ovmf-x86_64-debug-2017+git1510945757.b2662641d5-lp151.11.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ovmf / ovmf-tools / qemu-ovmf-x86_64 / qemu-ovmf-x86_64-debug / etc");
}
