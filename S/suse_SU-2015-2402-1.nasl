#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2402-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87724);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2015-8459",
    "CVE-2015-8460",
    "CVE-2015-8634",
    "CVE-2015-8635",
    "CVE-2015-8636",
    "CVE-2015-8638",
    "CVE-2015-8639",
    "CVE-2015-8640",
    "CVE-2015-8641",
    "CVE-2015-8642",
    "CVE-2015-8643",
    "CVE-2015-8644",
    "CVE-2015-8645",
    "CVE-2015-8646",
    "CVE-2015-8647",
    "CVE-2015-8648",
    "CVE-2015-8649",
    "CVE-2015-8650",
    "CVE-2015-8651"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"SUSE SLED11 Security Update : flash-player (SUSE-SU-2015:2402-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for flash-player fixes the following issues :

  - CVE-2015-8644: Type confusion vulnerability that could
    lead to code execution.

  - CVE-2015-8651: Integer overflow vulnerability that could
    lead to code execution.

  - CVE-2015-8634, CVE-2015-8635, CVE-2015-8638,
    CVE-2015-8639, CVE-2015-8640, CVE-2015-8641,
    CVE-2015-8642, CVE-2015-8643, CVE-2015-8646,
    CVE-2015-8647, CVE-2015-8648, CVE-2015-8649,
    CVE-2015-8650: Use-after-free vulnerabilities that could
    lead to code execution.

  - CVE-2015-8459, CVE-2015-8460, CVE-2015-8636,
    CVE-2015-8645: Memory corruption vulnerabilities that
    could lead to code execution.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=960317");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8459/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8460/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8634/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8635/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8636/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8638/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8639/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8640/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8641/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8642/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8643/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8644/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8645/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8646/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8647/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8648/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8649/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8650/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8651/");
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152402-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98511a93");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-flash-player-12291=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-flash-player-12291=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");

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
if (os_ver == "SLED11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-gnome-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"flash-player-kde4-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-gnome-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"flash-player-kde4-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-gnome-11.2.202.559-0.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"flash-player-kde4-11.2.202.559-0.32.1")) flag++;


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
