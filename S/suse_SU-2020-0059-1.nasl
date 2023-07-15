#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0059-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(132767);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-13173",
    "CVE-2019-9511",
    "CVE-2019-9512",
    "CVE-2019-9513",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2019-9516",
    "CVE-2019-9517",
    "CVE-2019-9518"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"SUSE SLES12 Security Update : nodejs12 (SUSE-SU-2020:0059-1) (0-Length Headers Leak) (Data Dribble) (Empty Frames Flood) (Internal Data Buffering) (Ping Flood) (Reset Flood) (Resource Loop) (Settings Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for nodejs12 fixes the following issues :

Update to LTS release 12.13.0 (jsc#SLE-8947).

Security issues fixed :

CVE-2019-9511: Fixed the HTTP/2 implementation that was vulnerable to
window size manipulations (bsc#1146091).

CVE-2019-9512: Fixed the HTTP/2 implementation that was vulnerable to
floods using PING frames (bsc#1146099).

CVE-2019-9513: Fixed the HTTP/2 implementation that was vulnerable to
resource loops, potentially leading to a denial of service
(bsc#1146094).

CVE-2019-9514: Fixed the HTTP/2 implementation that was vulnerable to
a reset flood, potentially leading to a denial of service
(bsc#1146095).

CVE-2019-9515: Fixed the HTTP/2 implementation that was vulnerable to
a SETTINGS frame flood (bsc#1146100).

CVE-2019-9516: Fixed the HTTP/2 implementation that was vulnerable to
a header leak, potentially leading to a denial of service
(bsc#1146090).

CVE-2019-9517: Fixed the HTTP/2 implementation that was vulnerable to
unconstrained interal data buffering (bsc#1146097).

CVE-2019-9518: Fixed the HTTP/2 implementation that was vulnerable to
a flood of empty frames, potentially leading to a denial of service
(bsc#1146093).

CVE-2019-13173: Fixed a file overwrite in the fstream.DirWriter()
function (bsc#1140290).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13173/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9511/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9512/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9513/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9514/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9515/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9516/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9517/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9518/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200059-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cadca2ae");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2020-59=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"nodejs12-12.13.0-1.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nodejs12-debuginfo-12.13.0-1.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nodejs12-debugsource-12.13.0-1.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nodejs12-devel-12.13.0-1.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"npm12-12.13.0-1.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs12");
}
