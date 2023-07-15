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
  script_id(66618);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-0401", "CVE-2013-1491", "CVE-2013-1537", "CVE-2013-1540", "CVE-2013-1557", "CVE-2013-1563", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2394", "CVE-2013-2417", "CVE-2013-2418", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2432", "CVE-2013-2433", "CVE-2013-2435", "CVE-2013-2440");

  script_name(english:"SuSE 10 Security Update : IBM Java (ZYPP Patch Number 8582)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.6.0 has been updated to SR13-FP2 fixing bugs and security
issues.

[http://www.ibm.com/developerworks/java/jdk/alerts/)(http://www.ibm.co
m/developerworks/java/jdk/alerts/)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2394.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2440.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8582.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-devel-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-fonts-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-plugin-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-32bit-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-alsa-32bit-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-devel-32bit-1.6.0_sr13.2-0.8.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-32bit-1.6.0_sr13.2-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
