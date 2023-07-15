#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-347.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(146897);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197"
  );
  script_xref(name:"IAVA", value:"2021-A-0112-S");

  script_name(english:"openSUSE Security Update : salt (openSUSE-2021-347)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for salt fixes the following issues :

  - Fix regression on cmd.run when passing tuples as cmd
    (bsc#1182740)

  - Allow `extra_filerefs` as sanitized `kwargs` for SSH
    client

  - Fix errors with virt.update

  - Fix for multiple for security issues (CVE-2020-28243)
    (CVE-2020-28972) (CVE-2020-35662) (CVE-2021-3148)
    (CVE-2021-3144) (CVE-2021-25281) (CVE-2021-25282)
    (CVE-2021-25283) (CVE-2021-25284) (CVE-2021-3197)
    (bsc#1181550) (bsc#1181556) (bsc#1181557) (bsc#1181558)
    (bsc#1181559) (bsc#1181560) (bsc#1181561) (bsc#1181562)
    (bsc#1181563) (bsc#1181564) (bsc#1181565)

  - virt: search for `grub.xen` path

  - Xen spicevmc, DNS SRV records backports :

  - Fix virtual network generated DNS XML for SRV records

  - Don't add spicevmc channel to xen VMs

  - virt UEFI fix: virt.update when `efi=True` 

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182740");
  script_set_attribute(attribute:"solution", value:
"Update the affected salt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-standalone-formulas-configuration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"python2-salt-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-salt-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-api-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-bash-completion-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-cloud-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-fish-completion-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-master-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-minion-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-proxy-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-ssh-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-standalone-formulas-configuration-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-syndic-3000-lp152.3.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"salt-zsh-completion-3000-lp152.3.27.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-salt / python3-salt / salt / salt-api / etc");
}
