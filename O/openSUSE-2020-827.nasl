#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-827.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138690);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2017-9103", "CVE-2017-9104", "CVE-2017-9105", "CVE-2017-9106", "CVE-2017-9107", "CVE-2017-9108", "CVE-2017-9109");

  script_name(english:"openSUSE Security Update : adns (openSUSE-2020-827)");
  script_summary(english:"Check for the openSUSE-2020-827 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for adns fixes the following issues :

  - CVE-2017-9103,CVE-2017-9104,CVE-2017-9105,CVE-2017-9109:
    Fixed an issue in local recursive resolver which could
    have led to remote code execution (bsc#1172265).

  - CVE-2017-9106: Fixed an issue with upstream DNS data
    sources which could have led to denial of service
    (bsc#1172265).

  - CVE-2017-9107: Fixed an issue when quering domain names
    which could have led to denial of service (bsc#1172265).

  - CVE-2017-9108: Fixed an issue which could have led to
    denial of service (bsc#1172265).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172265"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected adns packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:adns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:adns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:adns-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libadns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libadns-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libadns1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libadns1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libadns1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libadns1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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

if ( rpm_check(release:"SUSE15.1", reference:"adns-1.5.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"adns-debuginfo-1.5.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"adns-debugsource-1.5.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libadns-devel-1.5.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libadns1-1.5.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libadns1-debuginfo-1.5.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libadns-devel-32bit-1.5.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libadns1-32bit-1.5.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libadns1-32bit-debuginfo-1.5.1-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "adns / adns-debuginfo / adns-debugsource / libadns-devel / libadns1 / etc");
}
