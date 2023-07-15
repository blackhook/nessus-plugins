#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory solaris_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(119622);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2017-3623");

  script_name(english:"AIX 7.1 TL 4 : solaris (IJ10275)");
  script_summary(english:"Check for APAR IJ10275");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3623
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3623 An
unspecified vulnerability in Oracle Sun Systems related to the Solaris
Kernel RPC component could allow an unauthenticated attacker to take
control of the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/solaris_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3623");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.1", ml:"04", sp:"04", patch:"IJ10275s4a", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.33") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", sp:"05", patch:"IJ10275s5a", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.33") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", sp:"06", patch:"IJ10275s6a", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.33") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
