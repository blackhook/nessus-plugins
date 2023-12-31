#%NASL_MIN_LEVEL 999999

#@DEPRECATED@
#
# Disabled on 2014/03/10.  Deprecated by aix_U846347.nasl

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory icmp_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(63708);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/20  0:18:51");

  script_cve_id("CVE-2011-1385", "CVE-2012-0194");

  script_name(english:"AIX 5.3 TL 12 : icmp (IV13827)");
  script_summary(english:"Check for APAR IV13827");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There is an error in the handling of a particular ICMP packet in which
a remote user can cause a denial of service.

Note: The ifixes provided also contain the fix for CVE-2012-0194 since
they affect the same fileset.

See the following for CVE-2012-0194:
http://aix.software.ibm.com/aix/efixes/security/large_send_a
dvisory.asc."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/icmp_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, 'This plugin has been deprecated.  Use plugin #72842 (aix_U846347.nasl) instead.');

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"5.3", ml:"12", sp:"05", patch:"IV13827m05", package:"bos.net.tcp.client", minfilesetver:"5.3.12.0", maxfilesetver:"5.3.12.5") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
