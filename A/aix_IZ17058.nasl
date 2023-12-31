#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory nddstat_advisory.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64317);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2008-1599");

  script_name(english:"AIX 5.3 TL 0 : nddstat (IZ17058)");
  script_summary(english:"Check for APAR IZ17058");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The nddstat family of commands contains an environment variable
handling error. A local attacker may exploit this error to execute
arbitrary code with root privileges because the commands are setuid
root.

The following files are vulnerable :

/usr/sbin/atmstat /usr/sbin/entstat /usr/sbin/fddistat
/usr/sbin/hdlcstat /usr/sbin/tokstat."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/nddstat_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");
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

if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5a", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5b", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5c", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5d", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_5e", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6a", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6b", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6c", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6d", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.atm.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.61") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.ethernet.rte", minfilesetver:"5.3.0.60", maxfilesetver:"5.3.0.62") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.fddi.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.hdlc.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;
if (aix_check_ifix(release:"5.3", ml:"00", patch:"IZ17058_6e", package:"devices.common.IBM.tokenring.rte", minfilesetver:"5.3.0.50", maxfilesetver:"5.3.0.50") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
