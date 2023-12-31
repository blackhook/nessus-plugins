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
  script_id(65246);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2012-1541",
    "CVE-2012-3174",
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2013-0351",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0422",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0431",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0437",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0444",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0449",
    "CVE-2013-0450",
    "CVE-2013-1473",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1484",
    "CVE-2013-1485",
    "CVE-2013-1486",
    "CVE-2013-1487"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"SuSE 11.2 Security Update : Java (SAT Patch Number 7454)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 11 host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"IBM Java 7 was updated to SR4, fixing various critical security issues
and bugs.

Please see the IBM JDK Alert page for more information :

http://www.ibm.com/developerworks/java/jdk/alerts/

Security issues fixed :

  - / CVE-2012-3174. (CVE-2013-1487 / CVE-2013-1486 /
    CVE-2013-1478 / CVE-2013-0445 / CVE-2013-1480 /
    CVE-2013-0441 / CVE-2013-1476 / CVE-2012-1541 /
    CVE-2013-0446 / CVE-2012-3342 / CVE-2013-0442 /
    CVE-2013-0450 / CVE-2013-0425 / CVE-2013-0426 /
    CVE-2013-0428 / CVE-2012-3213 / CVE-2013-0419 /
    CVE-2013-0423 / CVE-2013-0351 / CVE-2013-0432 /
    CVE-2013-1473 / CVE-2013-0435 / CVE-2013-0434 /
    CVE-2013-0409 / CVE-2013-0427 / CVE-2013-0433 /
    CVE-2013-0424 / CVE-2013-0440 / CVE-2013-0438 /
    CVE-2013-0443 / CVE-2013-1484 / CVE-2013-1485 /
    CVE-2013-0437 / CVE-2013-0444 / CVE-2013-0449 /
    CVE-2013-0431 / CVE-2013-0422)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=798535");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1541.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-3174.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-3213.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-3342.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0351.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0409.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0419.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0422.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0423.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0424.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0425.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0426.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0427.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0428.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0431.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0432.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0433.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0434.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0435.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0437.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0438.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0440.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0441.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0442.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0443.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0444.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0445.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0446.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0449.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0450.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1473.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1476.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1478.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1480.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1484.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1485.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1486.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1487.html");
  script_set_attribute(attribute:"solution", value:
"Apply SAT patch number 7454.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet JMX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");

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
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_7_0-ibm-1.7.0_sr4.0-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_7_0-ibm-jdbc-1.7.0_sr4.0-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr4.0-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr4.0-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr4.0-0.6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
