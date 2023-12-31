#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory13.asc.
#
# @DEPRECATED@
#
# Disabled on 2017/07/20. Deprecated by aix_bind_advisory13.nasl.

include("compat.inc");

if (description)
{
  script_id(94968);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/20  0:18:51");

  script_cve_id("CVE-2016-2775", "CVE-2016-2776");
  script_xref(name:"IAVA", value:"2017-A-0004");

  script_name(english:"AIX 5.3 TL 12 : bind (IV90056) (deprecated)");
  script_summary(english:"Check for APAR IV90056");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2776
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2776 ISC BIND
is vulnerable to a denial of service, caused by an assertion failure
in buffer.c while a nameserver is building responses to a specifically
constructed request. By sending a specially crafted DNS packet, a
remote attacker could exploit this vulnerability to make named exit
unexpectedly with an assertion failure. ISC BIND is vulnerable to a
denial of service, caused by an error when lwresd or the named lwres
option is enabled. By sending an overly long request, a remote
attacker could exploit this vulnerability to cause the daemon to
crash.

This plugin has been deprecated to better accommodate iFix
supersedence with replacement plugin aix_bind_advisory13.nasl (plugin
id 102125)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind_advisory13.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use aix_bind_advisory13.nasl (plugin ID 102125) instead.");

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"5.3", ml:"12", sp:"09", patch:"IV90056m9a", package:"bos.net.tcp.client", minfilesetver:"5.3.12.0", maxfilesetver:"5.3.12.10") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"12", sp:"09", patch:"IV90056m9a", package:"bos.net.tcp.server", minfilesetver:"5.3.12.0", maxfilesetver:"5.3.12.6") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
