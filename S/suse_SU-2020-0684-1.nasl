#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0684-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(134622);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-17361", "CVE-2019-18897");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : salt (SUSE-SU-2020:0684-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for salt fixes the following issues :

Avoid possible user escalation upgrading salt-master (bsc#1157465)
(CVE-2019-18897)

Fix unit tests failures in test_batch_async tests

Batch Async: Handle exceptions, properly unregister and close
instances after running async batching to avoid CPU starvation of the
MWorkers (bsc#1162327)

RHEL/CentOS 8 uses platform-python instead of python3

New configuration option for selection of grains in the minion start
event.

Fix 'os_family' grain for Astra Linux Common Edition

Fix for salt-api NET API where unauthenticated attacker could run
arbitrary code (CVE-2019-17361) (bsc#1162504)

Adds disabled parameter to mod_repo in aptpkg module Move token with
atomic operation Bad API token files get deleted (bsc#1160931)

Support for Btrfs and XFS in parted and mkfs added

Adds list_downloaded for apt Module to enable pre-downloading support
Adds virt.(pool|network)_get_xml functions

Various libvirt updates :

  - Add virt.pool_capabilities function

  - virt.pool_running improvements

  - Add virt.pool_deleted state

  - virt.network_define allow adding IP configuration

virt: adding kernel boot parameters to libvirt xml

Fix to scheduler when data['run'] does not exist (bsc#1159118)

Fix virt states to not fail on VMs already stopped

Fix applying of attributes for returner rawfile_json (bsc#1158940)

xfs: do not fail if type is not present (bsc#1153611)

Fix errors when running virt.get_hypervisor function

Align virt.full_info fixes with upstream Salt

Fix for log checking in x509 test

Read repo info without using interpolation (bsc#1135656)

Limiting M2Crypto to >= SLE15

Replacing pycrypto with M2Crypto (bsc#1165425)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1135656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1157465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17361/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18897/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200684-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f79fe232");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2020-684=1

SUSE Linux Enterprise Module for Python2 15-SP1:zypper in -t patch
SUSE-SLE-Module-Python2-15-SP1-2020-684=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-684=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18897");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17361");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");

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

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"python2-salt-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-salt-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-api-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-cloud-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-doc-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-master-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-minion-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-proxy-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-ssh-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-standalone-formulas-configuration-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-syndic-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python2-salt-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-salt-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"salt-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"salt-doc-2019.2.0-6.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"salt-minion-2019.2.0-6.24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "salt");
}
