#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1868.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(142620);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0134");

  script_name(english:"openSUSE Security Update : salt (openSUSE-2020-1868)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for salt fixes the following issues :

  - Avoid regression on 'salt-master': set passphrase for
    salt-ssh keys to empty string (bsc#1178485)

  - Properly validate eauth credentials and tokens on SSH
    calls made by Salt API (bsc#1178319, bsc#1178362,
    bsc#1178361, CVE-2020-25592, CVE-2020-17490,
    CVE-2020-16846)

  - Fix disk.blkid to avoid unexpected keyword argument
    '__pub_user'. (bsc#1177867)

  - Ensure virt.update stop_on_reboot is updated with its
    default value.

  - Do not break package building for systemd OSes.

  - Drop wrong mock from chroot unit test.

  - Support systemd versions with dot. (bsc#1176294)

  - Fix for grains.test_core unit test.

  - Fix file/directory user and group ownership containing
    UTF-8 characters. (bsc#1176024)

  - Several changes to virtualization :

  - Fix virt update when cpu and memory are changed.

  - Memory Tuning GSoC.

  - Properly fix memory setting regression in virt.update.

  - Expose libvirt on_reboot in virt states.

  - Support transactional systems (MicroOS).

  - zypperpkg module ignores retcode 104 for search().
    (bsc#1159670)

  - Xen disk fixes. No longer generates volumes for Xen
    disks, but the corresponding file or block disk.
    (bsc#1175987)

  - Invalidate file list cache when cache file modified time
    is in the future. (bsc#1176397)

  - Prevent import errors when running test_btrfs unit tests

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178485");
  script_set_attribute(attribute:"solution", value:
"Update the affected salt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25592");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt REST API Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/09");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"python2-salt-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-salt-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-api-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-bash-completion-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-cloud-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-fish-completion-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-master-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-minion-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-proxy-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-ssh-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-standalone-formulas-configuration-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-syndic-3000-lp151.5.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-zsh-completion-3000-lp151.5.30.1") ) flag++;

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
