#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update asterisk-5524.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33894);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-1897", "CVE-2008-2119", "CVE-2008-3263", "CVE-2008-3264");

  script_name(english:"openSUSE 10 Security Update : asterisk (asterisk-5524)");
  script_summary(english:"Check for the asterisk-5524 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update fixes multiple security vulnerabilities in
asterisk (CVE-2008-1897, CVE-2008-2119, CVE-2008-3263, CVE-2008-3264)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:asterisk-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:asterisk-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:asterisk-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:asterisk-spandsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:asterisk-zaptel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"asterisk-1.2.13-31") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"asterisk-alsa-1.2.13-31") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"asterisk-odbc-1.2.13-31") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"asterisk-pgsql-1.2.13-31") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"asterisk-spandsp-1.2.13-31") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"asterisk-zaptel-1.2.13-31") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asterisk / asterisk-alsa / asterisk-odbc / asterisk-pgsql / etc");
}
