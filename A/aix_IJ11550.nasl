#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory xorg_advisory3.asc.
#

include("compat.inc");

if (description)
{
  script_id(119632);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2018-14665");

  script_name(english:"AIX 7.2 TL 3 : xorg (IJ11550)");
  script_summary(english:"Check for APAR IJ11550");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14665
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14665 X.Org X
server could allow a remote authenticated attacker to gain elevated
privileges on the system, caused by improper validation of command
line parameters. An attacker could exploit this vulnerability using
the -modulepath argument or the -logfile argument to overwrite
arbitrary files and execute unprivileged code on the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/xorg_advisory3.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Xorg X11 Server SUID logfile Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if (aix_check_ifix(release:"7.2", ml:"03", patch:"IJ11550s0a", package:"X11.base.rte", minfilesetver:"7.2.3.0", maxfilesetver:"7.2.3.15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
