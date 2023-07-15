#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1074.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(139012);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-15750",
    "CVE-2018-15751",
    "CVE-2020-11651",
    "CVE-2020-11652"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"openSUSE Security Update : salt (openSUSE-2020-1074)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for salt contains the following fixes :

  - Fix for TypeError in Tornado importer (bsc#1174165)

  - Require python3-distro only for TW (bsc#1173072)

  - Update to Salt version 3000: See release notes:
    https://docs.saltstack.com/en/latest/topics/releases/300
    0.html

  - Add docker.logout to docker execution module.
    (bsc#1165572)

  - Add option to enable/disable force refresh for zypper.

  - Add publish_batch to ClearFuncs exposed methods.

  - Adds test for zypper abbreviation fix.

  - Avoid segfault from 'salt-api' under certain conditions
    of heavy load managing SSH minions. (bsc#1169604)

  - Avoid traceback on debug logging for swarm module.
    (bsc#1172075)

  - Batch mode now also correctly provides return value.
    (bsc#1168340)

  - Better import cache handline.

  - Do not make file.recurse state to fail when msgpack
    0.5.4. (bsc#1167437)

  - Do not require vendored backports-abc. (bsc#1170288)

  - Fix errors from unit tests due NO_MOCK and
    NO_MOCK_REASON deprecation.

  - Fix for low rpm_lowpkg unit test.

  - Fix for temp folder definition in loader unit test.

  - Fix for unless requisite when pip is not installed.

  - Fix integration test failure for
    test_mod_del_repo_multiline_values.

  - Fix regression in service states with reload argument.

  - Fix tornado imports and missing _utils after rebasing
    patches.

  - Fix status attribute issue in aptpkg test.

  - Improved storage pool or network handling.

  - loop: fix variable names for until_no_eval.

  - Make 'salt.ext.tornado.gen' to use
    'salt.ext.backports_abc' on Python 2.

  - Make setup.py script not to require setuptools greater
    than 9.1.

  - More robust remote port detection.

  - Prevent sporious 'salt-api' stuck processes when
    managing SSH minions. because of logging deadlock.
    (bsc#1159284)

  - Python3.8 compatibility changes.

  - Removes unresolved merge conflict in yumpkg module.

  - Returns a the list of IPs filtered by the optional
    network list.

  - Revert broken changes to slspath made on Salt 3000
    (saltstack/salt#56341). (bsc#1170104)

  - Sanitize grains loaded from roster_grains.json cache
    during 'state.pkg'.

  - Various virt backports from 3000.2.

  - zypperpkg: filter patterns that start with dot.
    (bsc#1171906)

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174165");
  script_set_attribute(attribute:"see_also", value:"https://docs.saltstack.com/en/latest/topics/releases/3000.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected salt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt Master/Minion Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

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

if ( rpm_check(release:"SUSE15.1", reference:"python2-salt-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-salt-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-api-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-bash-completion-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-cloud-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-fish-completion-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-master-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-minion-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-proxy-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-ssh-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-standalone-formulas-configuration-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-syndic-3000-lp151.5.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-zsh-completion-3000-lp151.5.21.1") ) flag++;

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
