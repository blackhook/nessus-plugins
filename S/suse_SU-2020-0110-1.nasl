#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0110-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133032);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-12838", "CVE-2019-19727", "CVE-2019-19728");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : slurm (SUSE-SU-2020:0110-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for slurm to version 18.08.9 fixes the following issues :

Security issues fixed :

CVE-2019-19728: Fixed a privilege escalation with srun, where --uid
might have unintended side effects (bsc#1159692).

CVE-2019-12838: Fixed SchedMD Slurm SQL Injection issue (bnc#1140709).

CVE-2019-19727: Fixed permissions of slurmdbd.conf (bsc#1155784).

Bug fixes :

Fix ownership of /var/spool/slurm on new installations and upgrade
(bsc#1158696).

Fix %posttrans macro _res_update to cope with added newline
(bsc#1153259).

Move srun from 'slurm' to 'slurm-node': srun is required on the nodes
as well so sbatch will work. 'slurm-node' is a requirement when
'slurm' is installed (bsc#1153095).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12838/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19727/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19728/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200110-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35072979"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-110=1

SUSE Linux Enterprise Module for HPC 15-SP1 :

zypper in -t patch SUSE-SLE-Module-HPC-15-SP1-2020-110=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm33-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-config-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-openlava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-seff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sjstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpmi0-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpmi0-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libslurm33-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libslurm33-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"perl-slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"perl-slurm-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-auth-none-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-auth-none-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-config-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-config-man-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-devel-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-doc-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-lua-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-lua-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-munge-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-munge-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-node-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-node-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-pam_slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-pam_slurm-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-plugins-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-plugins-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-slurmdbd-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-slurmdbd-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-sql-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-sql-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-torque-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm-torque-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libpmi0-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libpmi0-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libslurm33-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"libslurm33-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"perl-slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"perl-slurm-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-auth-none-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-auth-none-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-config-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-config-man-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-devel-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-doc-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-lua-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-lua-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-munge-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-munge-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-node-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-node-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-pam_slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-pam_slurm-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-plugins-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-plugins-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-slurmdbd-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-slurmdbd-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-sql-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-sql-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-torque-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"slurm-torque-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slurm-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slurm-debugsource-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slurm-openlava-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slurm-seff-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slurm-sjstat-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slurm-sview-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"slurm-sview-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libpmi0-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libpmi0-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libslurm33-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"libslurm33-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"perl-slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"perl-slurm-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-auth-none-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-auth-none-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-config-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-config-man-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-devel-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-doc-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-lua-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-lua-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-munge-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-munge-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-node-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-node-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-pam_slurm-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-pam_slurm-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-plugins-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-plugins-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-slurmdbd-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-slurmdbd-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-sql-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-sql-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-torque-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"slurm-torque-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"slurm-debuginfo-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"slurm-debugsource-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"slurm-openlava-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"slurm-seff-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"slurm-sjstat-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"slurm-sview-18.08.9-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"slurm-sview-debuginfo-18.08.9-3.10.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/SQLi', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "slurm");
}
