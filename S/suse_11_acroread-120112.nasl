#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57586);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id("CVE-2011-2462", "CVE-2011-4369");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"SuSE 11.1 Security Update : Acrobat Reader (SAT Patch Number 5649)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 11 host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Acrobat Reader was updated to version 9.4.7 to fix two security
issues. (CVE-2011-2462 / CVE-2011-4369)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=735275");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-2462.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-4369.html");
  script_set_attribute(attribute:"solution", value:
"Apply SAT patch number 5649.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Reader U3D Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-9.4.7-0.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-cmaps-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-fonts-ja-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-fonts-ko-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-fonts-zh_CN-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"acroread-fonts-zh_TW-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-cmaps-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-fonts-ja-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-fonts-ko-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-fonts-zh_CN-9.4.6-0.4.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"acroread-fonts-zh_TW-9.4.6-0.4.2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
