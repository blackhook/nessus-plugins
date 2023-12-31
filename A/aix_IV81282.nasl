#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory11.asc.
#
# @DEPRECATED@
#
# Disabled on 2017/07/20. Deprecated by aix_bind_advisory11.nasl.

include("compat.inc");

if (description)
{
  script_id(90720);
  script_version("2.4");
  script_cvs_date("Date: 2018/07/20  0:18:51");

  script_cve_id("CVE-2015-8704");

  script_name(english:"AIX 7.2 TL 0 : bind (IV81282) (deprecated)");
  script_summary(english:"Check for APAR IV81282");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ISC BIND is vulnerable to a denial of service, caused by improper
bounds checking in apl_42.c. By sending specially crafted Address
Prefix List (APL) data, a remote authenticated attacker could exploit
this vulnerability to trigger an INSIST assertion failure and cause
the named process to terminate.

This plugin has been deprecated to better accommodate iFix
supersedence with replacement plugin aix_bind_advisory11.nasl (plugin
id 102123)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind_advisory11.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use aix_bind_advisory11.nasl (plugin ID 102123) instead.");

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.2", ml:"00", sp:"00", patch:"IV81282m0a", package:"bos.net.tcp.client", minfilesetver:"7.2.0.0", maxfilesetver:"7.2.0.0") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"00", sp:"01", patch:"IV81282m1a", package:"bos.net.tcp.client", minfilesetver:"7.2.0.0", maxfilesetver:"7.2.0.0") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
