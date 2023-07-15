#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1554-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(137593);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/21");

  script_cve_id("CVE-2020-12693");

  script_name(english:"SUSE SLES15 Security Update : slurm_20_02 (SUSE-SU-2020:1554-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for slurm_20_02 to version 20.02.3 fixes the following
issues :

Security issue fixed :

CVE-2020-12693: Fixed an authentication bypass via an alternate path
or channel (bsc#1172004).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12693/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201554-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dec3da2c"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for HPC 15-SP1 :

zypper in -t patch SUSE-SLE-Module-HPC-15-SP1-2020-1554=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12693");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm35-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-config-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-sview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-webdoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnss_slurm2-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnss_slurm2-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpmi0_20_02-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpmi0_20_02-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libslurm35-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libslurm35-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"perl-slurm_20_02-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"perl-slurm_20_02-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-auth-none-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-auth-none-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-config-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-config-man-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-debugsource-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-devel-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-doc-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-lua-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-lua-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-munge-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-munge-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-node-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-node-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-pam_slurm-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-pam_slurm-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-plugins-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-plugins-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-slurmdbd-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-slurmdbd-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-sql-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-sql-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-sview-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-sview-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-torque-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-torque-debuginfo-20.02.3-3.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"slurm_20_02-webdoc-20.02.3-3.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "slurm_20_02");
}
