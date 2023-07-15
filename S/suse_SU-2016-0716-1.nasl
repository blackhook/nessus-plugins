#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0716-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89921);
  script_version("2.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2016-0960",
    "CVE-2016-0961",
    "CVE-2016-0962",
    "CVE-2016-0963",
    "CVE-2016-0986",
    "CVE-2016-0987",
    "CVE-2016-0988",
    "CVE-2016-0989",
    "CVE-2016-0990",
    "CVE-2016-0991",
    "CVE-2016-0992",
    "CVE-2016-0993",
    "CVE-2016-0994",
    "CVE-2016-0995",
    "CVE-2016-0996",
    "CVE-2016-0997",
    "CVE-2016-0998",
    "CVE-2016-0999",
    "CVE-2016-1000",
    "CVE-2016-1001",
    "CVE-2016-1002",
    "CVE-2016-1005",
    "CVE-2016-1010"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"SUSE SLED11 Security Update : flash-player (SUSE-SU-2016:0716-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Adobe flash-player was updated to 11.2.202.577 to fix the following
list of security issues (bsc#970547) :

These updates resolve integer overflow vulnerabilities that could lead
to code execution (CVE-2016-0963, CVE-2016-0993, CVE-2016-1010).

These updates resolve use-after-free vulnerabilities that could lead
to code execution (CVE-2016-0987, CVE-2016-0988, CVE-2016-0990,
CVE-2016-0991, CVE-2016-0994, CVE-2016-0995, CVE-2016-0996,
CVE-2016-0997, CVE-2016-0998, CVE-2016-0999, CVE-2016-1000).

These updates resolve a heap overflow vulnerability that could lead to
code execution (CVE-2016-1001).

These updates resolve memory corruption vulnerabilities that could
lead to code execution (CVE-2016-0960, CVE-2016-0961, CVE-2016-0962,
CVE-2016-0986, CVE-2016-0989, CVE-2016-0992, CVE-2016-1002,
CVE-2016-1005).

Adobe advisory with more information:
https://helpx.adobe.com/security/products/flash-player/apsb16-08.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=970547");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0960/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0961/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0962/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0963/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0986/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0987/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0988/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0989/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0990/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0991/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0992/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0993/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0994/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0995/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0996/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0997/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0998/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0999/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1000/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1001/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1002/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1005/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1010/");
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160716-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c3355d3");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-flash-player-12443=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-11.2.202.577-0.38.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.577-0.38.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.577-0.38.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-11.2.202.577-0.38.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-gnome-11.2.202.577-0.38.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-kde4-11.2.202.577-0.38.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player");
}
