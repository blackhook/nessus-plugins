#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory iostat_advisory.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63764);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2008-2515");

  script_name(english:"AIX 5.2 TL 0 : iostat (IZ20635)");
  script_summary(english:"Check for APAR IZ20635");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The iostat command contains an environment variable handling error. A
local attacker may exploit this error to execute arbitrary code with
root privileges because the command is setuid root.

The following files are vulnerable :

/usr/bin/iostat."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/iostat_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
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

if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_08", package:"bos.acct", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.86") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_08", package:"bos.acct", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.95") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_08", package:"bos.acct", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.105") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_09", package:"bos.acct", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.86") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_09", package:"bos.acct", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.95") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_09", package:"bos.acct", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.105") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_10", package:"bos.acct", minfilesetver:"5.2.0.85", maxfilesetver:"5.2.0.86") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_10", package:"bos.acct", minfilesetver:"5.2.0.95", maxfilesetver:"5.2.0.95") < 0) flag++;
if (aix_check_ifix(release:"5.2", ml:"00", patch:"IZ20635_10", package:"bos.acct", minfilesetver:"5.2.0.105", maxfilesetver:"5.2.0.105") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
