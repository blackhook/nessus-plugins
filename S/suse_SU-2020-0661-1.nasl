#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0661-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(134561);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-12523",
    "CVE-2019-12526",
    "CVE-2019-12528",
    "CVE-2019-18676",
    "CVE-2019-18677",
    "CVE-2019-18678",
    "CVE-2019-18679",
    "CVE-2020-8449",
    "CVE-2020-8450",
    "CVE-2020-8517"
  );

  script_name(english:"SUSE SLES12 Security Update : squid (SUSE-SU-2020:0661-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for squid fixes the following issues :

CVE-2019-12528: Fixed an information disclosure flaw in the FTP
gateway (bsc#1162689).

CVE-2019-12526: Fixed potential remote code execution during URN
processing (bsc#1156326).

CVE-2019-12523,CVE-2019-18676: Fixed multiple improper validations in
URI processing (bsc#1156329).

CVE-2019-18677: Fixed Cross-Site Request Forgery in HTTP Request
processing (bsc#1156328).

CVE-2019-18678: Fixed incorrect message parsing which could have led
to HTTP request splitting issue (bsc#1156323).

CVE-2019-18679: Fixed information disclosure when processing HTTP
Digest Authentication (bsc#1156324).

CVE-2020-8449: Fixed a buffer overflow when squid is acting as
reverse-proxy (bsc#1162687).

CVE-2020-8450: Fixed a buffer overflow when squid is acting as
reverse-proxy (bsc#1162687).

CVE-2020-8517: Fixed a buffer overflow in ext_lm_group_acl when
processing NTLM Authentication credentials (bsc#1162691).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1156323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1156324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1156326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1156328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1156329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12523/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12526/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12528/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18676/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18677/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18678/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18679/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8449/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8450/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8517/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200661-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?176ea211");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2020-661=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2020-661=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2020-661=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2020-661=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2020-661=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2020-661=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2020-661=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2020-661=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2020-661=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2020-661=1

SUSE Enterprise Storage 5:zypper in -t patch SUSE-Storage-5-2020-661=1

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2020-661=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-12526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:squid-debugsource");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"squid-3.5.21-26.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"squid-debuginfo-3.5.21-26.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"squid-debugsource-3.5.21-26.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"squid-3.5.21-26.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"squid-debuginfo-3.5.21-26.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"squid-debugsource-3.5.21-26.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"squid-3.5.21-26.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"squid-debuginfo-3.5.21-26.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"squid-debugsource-3.5.21-26.20.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
