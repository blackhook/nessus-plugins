#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-639.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149598);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2020-14342", "CVE-2021-20208");

  script_name(english:"openSUSE Security Update : cifs-utils (openSUSE-2021-639)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for cifs-utils fixes the following security issues :

  - CVE-2021-20208: Fixed a potential kerberos auth leak
    escaping from container. (bsc#1183239)

  - CVE-2020-14342: Fixed a shell command injection
    vulnerability in mount.cifs. (bsc#1174477)

This update for cifs-utils fixes the following issues :

  - Solve invalid directory mounting. When attempting to
    change the current working directory into non-existing
    directories, mount.cifs crashes. (bsc#1152930)

  - Fixed a bug where it was no longer possible to mount
    CIFS filesystem after the last maintenance update.
    (bsc#1184815)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184815");
  script_set_attribute(attribute:"solution", value:
"Update the affected cifs-utils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20208");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14342");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cifs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cifs-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cifs-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cifs-utils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_cifscreds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_cifscreds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"cifs-utils-6.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cifs-utils-debuginfo-6.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cifs-utils-debugsource-6.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cifs-utils-devel-6.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pam_cifscreds-6.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pam_cifscreds-debuginfo-6.9-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cifs-utils / cifs-utils-debuginfo / cifs-utils-debugsource / etc");
}
