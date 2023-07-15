#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:4297-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120195);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2018-7187");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : containerd, docker / go (SUSE-SU-2018:4297-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for containerd, docker and go fixes the following issues :

containerd and docker :

Add backport for building containerd (bsc#1102522, bsc#1113313)

Upgrade to containerd v1.1.2, which is required for Docker
v18.06.1-ce. (bsc#1102522)

Enable seccomp support on SLE12 (fate#325877)

Update to containerd v1.1.1, which is the required version for the
Docker v18.06.0-ce upgrade. (bsc#1102522)

Put containerd under the podruntime slice (bsc#1086185)

3rd party registries used the default Docker certificate (bsc#1084533)

Handle build breakage due to missing 'export GOPATH' (caused by
resolution of boo#1119634). I believe Docker is one of the only
packages with this problem.

go: golang: arbitrary command execution via VCS path (bsc#1081495,
CVE-2018-7187)

Make profile.d/go.sh no longer set GOROOT=, in order to make switching
between versions no longer break. This ends up removing the need for
go.sh entirely (because GOPATH is also set automatically)
(boo#1119634)

Fix a regression that broke go get for import path patterns containing
'...' (bsc#1119706)

Additionally, the package go1.10 has been added.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114209"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119706"
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7187/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20184297-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17fe215c"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2018-3064=1

SUSE Linux Enterprise Module for Containers 15:zypper in -t patch
SUSE-SLE-Module-Containers-15-2018-3064=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.10-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"containerd-1.1.2-5.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"containerd-ctr-1.1.2-5.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debuginfo-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-debugsource-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-libnetwork-0.7.0.1+gitr2664_3ac297bc7fd0-4.3.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2664_3ac297bc7fd0-4.3.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-runc-1.0.0rc5+gitr3562_69663f0bd4b6-6.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-runc-debuginfo-1.0.0rc5+gitr3562_69663f0bd4b6-6.3.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-test-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"docker-test-debuginfo-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"go-1.10.4-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"go-doc-1.10.4-3.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"go1.10-1.10.7-1.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"go1.10-doc-1.10.7-1.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2664_3ac297bc7fd0-4.3.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"containerd-ctr-1.1.2-5.3.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-debuginfo-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-debugsource-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-test-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"docker-test-debuginfo-18.06.1_ce-6.8.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"go-1.10.4-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"go-doc-1.10.4-3.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"go1.10-1.10.7-1.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"go1.10-doc-1.10.7-1.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2664_3ac297bc7fd0-4.3.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / docker / go");
}
