#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-233.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122417);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12546", "CVE-2018-12550", "CVE-2018-12551");

  script_name(english:"openSUSE Security Update : mosquitto (openSUSE-2019-233)");
  script_summary(english:"Check for the openSUSE-2019-233 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mosquitto fixes the following issues :

Security issues fixed :

  - CVE-2018-12546: Fixed an issue with revoked access to
    topics (bsc#1125019).

  - CVE-2018-12551: Fixed an issue which allowed malformed
    data in the password file to be treated as valid
    (bsc#1125020).

  - CVE-2018-12550: Fixed an an issue which treats an empty
    ACL file wrongly (bsc#1125021)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125021"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mosquitto packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmosquitto1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmosquitto1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmosquittopp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmosquittopp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-clients-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/25");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libmosquitto1-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmosquitto1-debuginfo-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmosquittopp1-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmosquittopp1-debuginfo-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mosquitto-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mosquitto-clients-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mosquitto-clients-debuginfo-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mosquitto-debuginfo-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mosquitto-debugsource-1.4.15-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"mosquitto-devel-1.4.15-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmosquitto1 / libmosquitto1-debuginfo / libmosquittopp1 / etc");
}
