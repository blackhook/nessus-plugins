#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52752);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4452", "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465", "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4471", "CVE-2010-4473", "CVE-2010-4475", "CVE-2010-4476");

  script_name(english:"SuSE 10 Security Update : java-1_6_0-ibm, java-1_6_0-ibm-32bit, java-1_6_0-ibm-64bit, java-1_6_0-ibm-alsa, java-1_6_0-ibm-alsa-32bit, java-1_6_0-ibm-demo, java-1_6_0-ibm-devel, java-1_6_0-ibm-devel-32bit, java-1_6_0-ibm-fonts, java-1_6_0-ibm-jdbc, java-1_6_0-ibm-jdbc-32bit, java-1_6_0-ibm-jdbc-64bit, java-1_6_0-ibm-plugin, java-1_6_0-ibm-plugin-32bit, java-1_6_0-ibm-src (ZYPP Patch Number 7369)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 6 SR9 FP1 was updated to fix a critical security bug in float
number handling :

  - The Java Runtime Environment hangs forever when
    converting '2.2250738585072012e-308' to a binary
    floating-point number. (CVE-2010-4476)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4447.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4448.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4452.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4454.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4462.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4465.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4467.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4468.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4475.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4476.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7369.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Applet2ClassLoader Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-devel-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-fonts-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-plugin-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-32bit-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-alsa-32bit-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-devel-32bit-1.6.0_sr9.1-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-32bit-1.6.0_sr9.1-1.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
