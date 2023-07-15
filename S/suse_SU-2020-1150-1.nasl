#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1150-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(136169);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-11651", "CVE-2020-11652");
  script_xref(name:"IAVA", value:"2020-A-0195-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : salt (SUSE-SU-2020:1150-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for salt fixes the following issues :

Fix CVE-2020-11651 and CVE-2020-11652 (bsc#1170595)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11651/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11652/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201150-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85e05fec");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2020-1150=1

SUSE Linux Enterprise Module for Python2 15-SP1:zypper in -t patch
SUSE-SLE-Module-Python2-15-SP1-2020-1150=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-1150=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt Master/Minion Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

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
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (rpm_check(release:"SLES15", sp:"1", reference:"python2-salt-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-salt-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-api-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-cloud-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-doc-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-master-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-minion-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-proxy-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-ssh-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-standalone-formulas-configuration-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-syndic-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python2-salt-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-salt-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"salt-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"salt-doc-2019.2.0-6.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"salt-minion-2019.2.0-6.27.1")) flag++;


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
