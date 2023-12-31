#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory12.asc.
#
# @DEPRECATED@
#
# Disabled on 2017/07/20. Deprecated by aix_bind_advisory12.nasl.

include("compat.inc");

if (description)
{
  script_id(91678);
  script_version("2.6");
  script_cvs_date("Date: 2018/07/20  0:18:51");

  script_cve_id("CVE-2016-1285", "CVE-2016-1286");

  script_name(english:"AIX 6.1 TL 9 : bind (IV84456) (deprecated)");
  script_summary(english:"Check for APAR IV84456");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1285 ISC BIND
is vulnerable to a denial of service, caused by the improper handling
of control channel input. By sending a specially crafted packet, a
remote attacker could exploit this vulnerability to trigger an
assertion failure in sexpr.c or alist.c and cause the named process to
crash. ISC BIND is vulnerable to a denial of service, caused by an
error when parsing signature records for DNAME resource records. A
remote attacker could exploit this vulnerability to trigger an
assertion failure in resolver.c or db.c and cause the named process to
crash.

This plugin has been deprecated to better accommodate iFix
supersedence with replacement plugin aix_bind_advisory12.nasl (plugin
id 102124)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind_advisory12.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use aix_bind_advisory12.nasl (plugin ID 102124) instead.");

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"6.1", ml:"09", sp:"05", patch:"IV84456s5b", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.102") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"05", patch:"IV84456s5b", package:"bos.net.tcp.server", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.101") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"06", patch:"IV84456s6a", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.102") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"06", patch:"IV84456s6a", package:"bos.net.tcp.server", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.101") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"07", patch:"IV84456s7a", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.102") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"07", patch:"IV84456s7a", package:"bos.net.tcp.server", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.101") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
