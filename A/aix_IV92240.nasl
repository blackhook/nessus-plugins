#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bellmail_advisory2.asc.
#
# @DEPRECATED@
#
# Disabled on 2017/07/20. Deprecated by aix_bellmail_advisory2.nasl.

include("compat.inc");

if (description)
{
  script_id(96835);
  script_version("3.8");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_cve_id("CVE-2017-1093");

  script_name(english:"AIX 7.1 TL 4 : bellmail (IV92240) (deprecated)");
  script_summary(english:"Check for APAR IV92240");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1093
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1093 IBM AIX
could allow a local user to exploit a vulnerability in the bellmail
binary to gain root privileges.

This plugin has been deprecated to better accommodate iFix
supersedence with replacement plugin aix_bellmail_advisory2.nasl
(plugin id 102121)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bellmail_advisory2.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use aix_bellmail_advisory2.nasl (plugin ID 102121) instead.");

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.1", ml:"04", sp:"01", patch:"IV92240m3a", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.30") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", sp:"02", patch:"IV92240m3a", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.30") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", sp:"03", patch:"IV92240m3a", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.30") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
