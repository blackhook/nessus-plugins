#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0435-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146460);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2020-15257", "CVE-2021-21284", "CVE-2021-21285");

  script_name(english:"SUSE SLES15 Security Update : containerd, docker, docker-runc, golang-github-docker-libnetwork (SUSE-SU-2021:0435-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork fixes the following issues :

Security issues fixed :

CVE-2020-15257: Fixed a privilege escalation in containerd
(bsc#1178969).

CVE-2021-21284: potential privilege escalation when the root user in
the remapped namespace has access to the host filesystem (bsc#1181732)

CVE-2021-21285: pulling a malformed Docker image manifest crashes the
dockerd daemon (bsc#1181730)

Non-security issues fixed :

Update Docker to 19.03.15-ce. See upstream changelog in the packaged
/usr/share/doc/packages/docker/CHANGELOG.md. This update includes
fixes for bsc#1181732 (CVE-2021-21284) and bsc#1181730
(CVE-2021-21285).

Only apply the boo#1178801 libnetwork patch to handle firewalld on
openSUSE. It appears that SLES doesn't like the patch. (bsc#1180401)

Update to containerd v1.3.9, which is needed for Docker v19.03.14-ce
and fixes CVE-2020-15257. bsc#1180243

Update to containerd v1.3.7, which is required for Docker 19.03.13-ce.
bsc#1176708

Update to Docker 19.03.14-ce. See upstream changelog in the packaged
/usr/share/doc/packages/docker/CHANGELOG.md. CVE-2020-15257
bsc#1180243 https://github.com/docker/docker-ce/releases/tag/v19.03.14

Enable fish-completion

Add a patch which makes Docker compatible with firewalld with nftables
backend. Backport of https://github.com/moby/libnetwork/pull/2548
(bsc#1178801, SLE-16460)

Update to Docker 19.03.13-ce. See upstream changelog in the packaged
/usr/share/doc/packages/docker/CHANGELOG.md. bsc#1176708

Fixes for %_libexecdir changing to /usr/libexec (bsc#1174075)

Emergency fix: %requires_eq does not work with provide symbols, only
effective package names. Convert back to regular Requires.

Update to Docker 19.03.12-ce. See upstream changelog in the packaged
/usr/share/doc/packages/docker/CHANGELOG.md.

Use Go 1.13 instead of Go 1.14 because Go 1.14 can cause all sorts of
spurrious errors due to Go returning -EINTR from I/O syscalls much
more often (due to Go 1.14's pre-emptive goroutine support).

Add BuildRequires for all -git dependencies so that we catch missing
dependencies much more quickly.

Update to libnetwork 55e924b8a842, which is required for Docker
19.03.14-ce. bsc#1180243

Add patch which makes libnetwork compatible with firewalld with
nftables backend. Backport of
https://github.com/moby/libnetwork/pull/2548 (bsc#1178801, SLE-16460)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181732");
  script_set_attribute(attribute:"see_also", value:"https://github.com/docker/docker-ce/releases/tag/v19.03.14");
  script_set_attribute(attribute:"see_also", value:"https://github.com/moby/libnetwork/pull/2548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15257/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21284/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21285/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210435-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fccb77db");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-435=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-435=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-435=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-435=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-435=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-435=1

SUSE Linux Enterprise Module for Containers 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Containers-15-SP3-2021-435=1

SUSE Linux Enterprise Module for Containers 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Containers-15-SP2-2021-435=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-435=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-435=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-435=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15257");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"containerd-1.3.9-5.29.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-19.03.15_ce-6.43.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-debuginfo-19.03.15_ce-6.43.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-libnetwork-0.7.0.1+gitr2908_55e924b8a842-4.28.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2908_55e924b8a842-4.28.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-runc-1.0.0rc10+gitr3981_dc9208a3303f-6.45.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"docker-runc-debuginfo-1.0.0rc10+gitr3981_dc9208a3303f-6.45.3")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"containerd-1.3.9-5.29.3")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"docker-19.03.15_ce-6.43.3")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"docker-debuginfo-19.03.15_ce-6.43.3")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"docker-libnetwork-0.7.0.1+gitr2908_55e924b8a842-4.28.3")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2908_55e924b8a842-4.28.3")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"docker-runc-1.0.0rc10+gitr3981_dc9208a3303f-6.45.3")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"docker-runc-debuginfo-1.0.0rc10+gitr3981_dc9208a3303f-6.45.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"containerd-1.3.9-5.29.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"docker-19.03.15_ce-6.43.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"docker-debuginfo-19.03.15_ce-6.43.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"docker-libnetwork-0.7.0.1+gitr2908_55e924b8a842-4.28.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2908_55e924b8a842-4.28.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"docker-runc-1.0.0rc10+gitr3981_dc9208a3303f-6.45.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"docker-runc-debuginfo-1.0.0rc10+gitr3981_dc9208a3303f-6.45.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / docker / docker-runc / golang-github-docker-libnetwork");
}
