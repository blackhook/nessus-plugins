#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update samba-3828.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27432);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2447");

  script_name(english:"openSUSE 10 Security Update : samba (samba-3828)");
  script_summary(english:"Check for the samba-3828 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The previous security fix for CVE-2007-2447 missed one character in
the shell escape handling.

Also fixed were some regressions introduced by the previous update."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cifs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmsrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmsrpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-pdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-vscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.2", reference:"cifs-mount-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"ldapsmb-1.34b-27.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libmsrpc-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libmsrpc-devel-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libsmbclient-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libsmbclient-devel-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-client-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-pdb-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-python-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-vscan-0.3.6b-98.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"samba-winbind-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"libsmbclient-32bit-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-32bit-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-client-32bit-3.0.23d-19.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.23d-19.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
