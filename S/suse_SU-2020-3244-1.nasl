#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3244-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143761);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0134");

  script_name(english:"SUSE SLES15 Security Update : Salt (SUSE-SU-2020:3244-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update fixes the following issues :

salt :

Avoid regression on 'salt-master': set passphrase for salt-ssh keys to
empty string (bsc#1178485)

Properly validate eauth credentials and tokens on SSH calls made by
Salt API (bsc#1178319, bsc#1178362, bsc#1178361, CVE-2020-25592,
CVE-2020-17490, CVE-2020-16846)

Fix disk.blkid to avoid unexpected keyword argument '__pub_user'
(bsc#1177867)

Ensure virt.update stop_on_reboot is updated with its default value

Do not break package building for systemd OSes

Drop wrong mock from chroot unit test

Support systemd versions with dot (bsc#1176294)

Fix for grains.test_core unit test

Fix file/directory user and group ownership containing UTF-8
characters (bsc#1176024)

Several changes to virtualization :

  - Fix virt update when cpu and memory are changed

  - Memory Tuning GSoC

  - Properly fix memory setting regression in virt.update

  - Expose libvirt on_reboot in virt states

Support transactional systems (MicroOS)

Zypperpkg module ignores retcode 104 for search() (bsc#1159670)

Xen disk fixes. No longer generates volumes for Xen disks, but the
corresponding file or block disk (bsc#1175987)

Invalidate file list cache when cache file modified time is in the
future (bsc#1176397)

Prevent import errors when running test_btrfs unit tests

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16846/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-17490/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25592/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203244-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bfec39b");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-3244=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-3244=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3244=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3244=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25592");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt REST API Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

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
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python2-salt-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python3-salt-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-api-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-cloud-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-doc-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-master-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-minion-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-proxy-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-ssh-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-standalone-formulas-configuration-3000-5.91.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"salt-syndic-3000-5.91.1")) flag++;


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
