#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0068-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105764);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLES11 Security Update : microcode_ctl (SUSE-SU-2018:0068-1) (Spectre)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to Intel microcode version 20180108 (bsc#1075262 CVE-2017-5715)

  - The pre-released microcode fixing some important
    security issues is now officially published (and
    included in the added tarball). Among other updates it
    contains :

  - IVT C0 (06-3e-04:ed) 428->42a

  - SKL-U/Y D0 (06-4e-03:c0) ba->c2

  - BDW-U/Y E/F (06-3d-04:c0) 25->28

  - HSW-ULT Cx/Dx (06-45-01:72) 20->21

  - Crystalwell Cx (06-46-01:32) 17->18

  - BDW-H E/G (06-47-01:22) 17->1b

  - HSX-EX E0 (06-3f-04:80) 0f->10

  - SKL-H/S R0 (06-5e-03:36) ba->c2

  - HSW Cx/Dx (06-3c-03:32) 22->23

  - HSX C0 (06-3f-02:6f) 3a->3b

  - BDX-DE V0/V1 (06-56-02:10) 0f->14

  - BDX-DE V2 (06-56-03:10) 700000d->7000011

  - KBL-U/Y H0 (06-8e-09:c0) 62->80

  - KBL Y0 / CFL D0 (06-8e-0a:c0) 70->80

  - KBL-H/S B0 (06-9e-09:2a) 5e->80

  - CFL U0 (06-9e-0a:22) 70->80

  - CFL B0 (06-9e-0b:02) 72->80

  - SKX H0 (06-55-04:b7) 2000035->200003c

  - GLK B0 (06-7a-01:01) 1e->22

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180068-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bb3de65"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-microcode_ctl-13406=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-microcode_ctl-13406=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-microcode_ctl-13406=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:microcode_ctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"microcode_ctl-1.17-102.83.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"microcode_ctl-1.17-102.83.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"microcode_ctl-1.17-102.83.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"microcode_ctl-1.17-102.83.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "microcode_ctl");
}
