#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0035-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(132743);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-16884");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : containerd, docker, docker-runc, golang-github-docker-libnetwork (SUSE-SU-2020:0035-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork fixes the following issues :

Security issue fixed :

CVE-2019-16884: Fixed incomplete patch for LSM bypass via malicious
Docker image that mount over a /proc directory (bsc#1152308).

Bug fixes: Update to Docker 19.03.5-ce (bsc#1158590).

Update to Docker 19.03.3-ce (bsc#1153367).

Update to Docker 19.03.2-ce (bsc#1150397).

Fixed default installation such that --userns-remap=default works
properly (bsc#1143349).

Fixed nginx blocked by apparmor (bsc#1122469).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1150397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-16884/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200035-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c485953c"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-35=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2020-35=1

SUSE Linux Enterprise Module for Containers 15-SP1:zypper in -t patch
SUSE-SLE-Module-Containers-15-SP1-2020-35=1

SUSE Linux Enterprise Module for Containers 15:zypper in -t patch
SUSE-SLE-Module-Containers-15-2020-35=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd-kubic-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-kubic-kubeadm-criconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-kubic-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-kubic-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-docker-libnetwork-kubic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"containerd-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"containerd-ctr-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"containerd-kubic-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"containerd-kubic-ctr-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-kubic-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-kubic-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-kubic-kubeadm-criconfig-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-kubic-test-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-kubic-test-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-libnetwork-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-libnetwork-kubic-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-libnetwork-kubic-debuginfo-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-runc-1.0.0rc8+gitr3917_3e425f80a8c9-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-runc-debuginfo-1.0.0rc8+gitr3917_3e425f80a8c9-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-runc-kubic-1.0.0rc8+gitr3917_3e425f80a8c9-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-runc-kubic-debuginfo-1.0.0rc8+gitr3917_3e425f80a8c9-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-test-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-test-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"golang-github-docker-libnetwork-kubic-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"containerd-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"containerd-ctr-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-libnetwork-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-runc-1.0.0rc8+gitr3917_3e425f80a8c9-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-runc-debuginfo-1.0.0rc8+gitr3917_3e425f80a8c9-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-test-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-test-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"containerd-ctr-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"containerd-kubic-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"containerd-kubic-ctr-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-kubic-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-kubic-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-kubic-kubeadm-criconfig-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-kubic-test-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-kubic-test-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-libnetwork-kubic-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-libnetwork-kubic-debuginfo-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-runc-kubic-1.0.0rc8+gitr3917_3e425f80a8c9-6.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-runc-kubic-debuginfo-1.0.0rc8+gitr3917_3e425f80a8c9-6.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-test-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"docker-test-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"golang-github-docker-libnetwork-kubic-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"containerd-ctr-1.2.10-5.19.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-test-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-test-debuginfo-19.03.5_ce-6.31.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2877_3eb39382bfa6-4.18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / docker / docker-runc / golang-github-docker-libnetwork");
}
