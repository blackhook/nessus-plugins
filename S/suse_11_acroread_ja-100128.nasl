#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44377);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2009-3953",
    "CVE-2009-3954",
    "CVE-2009-3955",
    "CVE-2009-3956",
    "CVE-2009-3957",
    "CVE-2009-3958",
    "CVE-2009-3959",
    "CVE-2009-4324"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"SuSE 11 Security Update : acroread_ja (SAT Patch Number 1881)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 11 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Specially crafted PDF files could crash acroread. Attackers could
exploit that to potentially execute arbitrary code. (CVE-2009-3953 /
CVE-2009-3954 / CVE-2009-3955 / CVE-2009-3956 / CVE-2009-3957 /
CVE-2009-3958 / CVE-2009-3959 / CVE-2009-4324)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=564742");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3953.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3955.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3956.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3957.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3958.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-3959.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-4324.html");
  script_set_attribute(attribute:"solution", value:
"Apply SAT patch number 1881.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Doc.media.newPlayer Use After Free Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(16, 94, 119, 189, 399);

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread_ja");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"acroread_ja-9.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
