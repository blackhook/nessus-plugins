#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory cmdque_advisory.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70274);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2013-5419");
  script_bugtraq_id(62796);

  script_name(english:"AIX 6.1 TL 7 : cmdque (IV47427)");
  script_summary(english:"Check for APAR IV47427");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Printer commands mkque and mkquedev are susceptible to buffer overflow
by users belonging to the 'printq' group. These commands are owned by
'root' and SUID bit set. The group is set to 'printq'. By default, no
users are belong to the 'printq'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/cmdque_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (aix_check_ifix(release:"6.1", ml:"07", sp:"08", patch:"IV47427s8b", package:"bos.rte.printers", minfilesetver:"6.1.7.0", maxfilesetver:"6.1.7.16") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
