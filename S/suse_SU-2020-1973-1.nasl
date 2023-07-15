#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1973-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(138794);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-18897", "CVE-2020-11651", "CVE-2020-11652");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"SUSE SLES15 Security Update : Salt (SUSE-SU-2020:1973-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update fixes the following issues :

salt :

Fix for TypeError in Tornado importer (bsc#1174165)

Require python3-distro only for TW (bsc#1173072)

Various virt backports from 3000.2

Avoid traceback on debug logging for swarm module (bsc#1172075)

Add publish_batch to ClearFuncs exposed methods

Update to salt version 3000 See release notes:
https://docs.saltstack.com/en/latest/topics/releases/3000.html

Zypperpkg: filter patterns that start with dot (bsc#1171906)

Batch mode now also correctly provides return value (bsc#1168340)

Add docker.logout to docker execution module (bsc#1165572)

Testsuite fix

Add option to enable/disable force refresh for zypper

Python3.8 compatibility changes

Prevent sporious 'salt-api' stuck processes when managing SSH minions
because of logging deadlock (bsc#1159284)

Avoid segfault from 'salt-api' under certain conditions of heavy load
managing SSH minions (bsc#1169604)

Revert broken changes to slspath made on Salt 3000
(saltstack/salt#56341) (bsc#1170104)

Returns a the list of IPs filtered by the optional network list

Fix CVE-2020-11651 and CVE-2020-11652 (bsc#1170595)

Do not require vendored backports-abc (bsc#1170288)

Fix partition.mkpart to work without fstype (bsc#1169800)

Enable building and installation for Fedora

Disable python2 build on Tumbleweed We are removing the python2
interpreter from openSUSE (SLE16). As such disable salt building for
python2 there.

More robust remote port detection

Sanitize grains loaded from roster_grains.json cache during
'state.pkg'

Do not make file.recurse state to fail when msgpack 0.5.4
(bsc#1167437)

Build: Buildequire pkgconfig(systemd) instead of systemd
pkgconfig(systemd) is provided by systemd, so this is de-facto no
change. But inside the Open Build Service (OBS), the same symbol is
also provided by systemd-mini, which exists to shorten build-chains by
only enabling what other packages need to successfully build

Add new custom SUSE capability for saltutil state module

Fixes status attribute issue in aptpkg test

Make setup.py script not to require setuptools greater than 9.1

Loop: fix variable names for until_no_eval

Drop conflictive module.run state patch (bsc#1167437)

Update patches after rebase with upstream v3000 tag (bsc#1167437)

Fix some requirements issues depending on Python3 versions

Removes obsolete patch

Fix for low rpm_lowpkg unit test

Add python-singledispatch as dependency for python2-salt

Virt._get_domain: don't raise an exception if there is no VM

Fix for temp folder definition in loader unit test

Adds test for zypper abbreviation fix

Improved storage pool or network handling

Better import cache handline

Make 'salt.ext.tornado.gen' to use 'salt.ext.backports_abc' on Python
2

Fix regression in service states with reload argument

Fix integration test failure for test_mod_del_repo_multiline_values

Fix for unless requisite when pip is not installed

Fix errors from unit tests due NO_MOCK and NO_MOCK_REASON deprecation

Fix tornado imports and missing _utils after rebasing patches

Removes unresolved merge conflict in yumpkg module

Use full option name instead of undocumented abbreviation for zypper

Requiring python3-distro only for openSUSE/SLE >= 15 and not for
Python 2 builds

Avoid possible user escalation upgrading salt-master (bsc#1157465)
(CVE-2019-18897)

Fix unit tests failures in test_batch_async tests

Batch Async: Handle exceptions, properly unregister and close
instances after running async batching to avoid CPU starvation of the
MWorkers (bsc#1162327)

RHEL/CentOS 8 uses platform-python instead of python3

Loader: invalidate the import cachefor extra modules

Zypperpkg: filter patterns that start with dot (bsc#1171906)

Batch mode now also correctly provides return value (bsc#1168340)

Add docker.logout to docker execution module (bsc#1165572)

Improvements for chroot module

Add option to enable/disable force refresh for zypper

Prevent sporious 'salt-api' stuck processes when managing SSH minions
because of logging deadlock (bsc#1159284)

Avoid segfault from 'salt-api' under certain conditions of heavy load
managing SSH minions (bsc#1169604)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1157465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174165");
  script_set_attribute(attribute:"see_also", value:"https://docs.saltstack.com/en/latest/topics/releases/3000.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18897/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11651/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11652/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201973-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b40e28d");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-1973=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-1973=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-1973=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-1973=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt Master/Minion Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-standalone-formulas-configuration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python2-salt-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python3-salt-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-api-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-cloud-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-doc-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-master-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-minion-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-proxy-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-ssh-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-standalone-formulas-configuration-3000-5.78.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-syndic-3000-5.78.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Salt");
}
