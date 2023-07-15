#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0286-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122050);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : docker (SUSE-SU-2019:0286-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for containerd, docker, docker-runc and
golang-github-docker-libnetwork fixes the following issues :

Security issues fixed for containerd, docker, docker-runc and
golang-github-docker-libnetwork :

CVE-2018-16873: cmd/go: remote command execution during 'go get -u'
(bsc#1118897)

CVE-2018-16874: cmd/go: directory traversal in 'go get' via curly
braces in import paths (bsc#1118898)

CVE-2018-16875: crypto/x509: CPU denial of service (bsc#1118899)

Non-security issues fixed for docker: Disable leap based builds for
kubic flavor (bsc#1121412)

Allow users to explicitly specify the NIS domainname of a container
(bsc#1001161)

Update docker.service to match upstream and avoid rlimit problems
(bsc#1112980)

Allow docker images larger then 23GB (bsc#1118990)

Docker version update to version 18.09.0-ce (bsc#1115464)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1001161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16873/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16874/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16875/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190286-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02aeb83a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-286=1

SUSE Linux Enterprise Module for Containers 15:zypper in -t patch
SUSE-SLE-Module-Containers-15-2019-286=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16874");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"containerd-1.1.2-5.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"containerd-ctr-1.1.2-5.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debuginfo-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debugsource-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-libnetwork-0.7.0.1+gitr2704_6da50d197830-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2704_6da50d197830-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-runc-1.0.0rc5+gitr3562_69663f0bd4b6-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-runc-debuginfo-1.0.0rc5+gitr3562_69663f0bd4b6-6.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-test-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-test-debuginfo-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2704_6da50d197830-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"containerd-ctr-1.1.2-5.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-debuginfo-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-debugsource-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-test-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-test-debuginfo-18.09.0_ce-6.11.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2704_6da50d197830-4.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker");
}
