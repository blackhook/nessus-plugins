#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1060.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(138985);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2020-13625",
    "CVE-2020-14295"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : cacti / cacti-spine (openSUSE-2020-1060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for cacti, cacti-spine fixes the following issues :

  - cacti 1.2.13 :

  - Query XSS vulnerabilities require vendor package update
    (CVE-2020-11022 / CVE-2020-11023)

  - Lack of escaping on some pages can lead to XSS exposure

  - Update PHPMailer to 6.1.6 (CVE-2020-13625)

  - SQL Injection vulnerability due to input validation
    failure when editing colors (CVE-2020-14295,
    boo#1173090)

  - Lack of escaping on template import can lead to XSS
    exposure

  - switch from cron to systemd timers (boo#1115436) :

  + cacti-cron.timer

  + cacti-cron.service

  - avoid potential root escalation on systems with
    fs.protected_hardlinks=0 (boo#1154087): handle directory
    permissions in file section instead of using chown
    during post installation

  - rewrote apache configuration to get rid of .htaccess
    files and explicitely disable directory permissions per
    default (only allow a limited, well-known set of
    directories)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173090");
  script_set_attribute(attribute:"solution", value:
"Update the affected cacti / cacti-spine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14295");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti color filter authenticated SQLi to RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"cacti-1.2.13-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cacti-spine-1.2.13-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cacti-spine-debuginfo-1.2.13-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cacti-spine-debugsource-1.2.13-lp151.3.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cacti-1.2.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cacti-spine-1.2.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cacti-spine-debuginfo-1.2.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"cacti-spine-debugsource-1.2.13-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cacti-spine / cacti-spine-debuginfo / cacti-spine-debugsource / etc");
}
