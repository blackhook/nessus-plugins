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
  script_id(64170);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id(
    "CVE-2012-0547",
    "CVE-2012-0551",
    "CVE-2012-1682",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1717",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1721",
    "CVE-2012-1722",
    "CVE-2012-1725",
    "CVE-2012-1726",
    "CVE-2012-3136",
    "CVE-2012-4681"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"SuSE 11.2 Security Update : IBM Java (SAT Patch Number 6839)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 11 host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"IBM Java 1.7.0 was updated to SR2 which fixes critical security
issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=780897");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-0547.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-0551.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1682.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1713.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1716.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1717.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1718.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1719.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1721.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1722.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1725.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1726.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-3136.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-4681.html");
  script_set_attribute(attribute:"solution", value:
"Apply SAT patch number 6839.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java 7 Applet Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_7_0-ibm-1.7.0_sr2.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_7_0-ibm-jdbc-1.7.0_sr2.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr2.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr2.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr2.0-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
