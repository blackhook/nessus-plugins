#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ldapauth_advisory2.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63714);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2012-0745");

  script_name(english:"AIX 6.1 TL 5 : ldapauth (IV19097)");
  script_summary(english:"Check for APAR IV19097");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"AIX could allow a local attacker to gain elevated privileges on the
system, caused by an error in the getpwnam() function when customer
extended LDAP user filtering is configured. A local attacker could
exploit this vulnerability to gain lateral or elevated privileges on
the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/ldapauth_advisory2.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"6.1", ml:"05", sp:"08", patch:"IV19097s8", package:"bos.rte.security", minfilesetver:"6.1.5.0", maxfilesetver:"6.1.5.7") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
