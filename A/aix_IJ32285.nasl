#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ksh_advisory.asc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(152172);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2021-29741");

  script_name(english:"AIX 7.2 TL 3 : ksh (IJ32285)");
  script_summary(english:"Check for APAR IJ32285");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29741
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29741 IBM AIX
could allow a local user to exploit a vulnerability in Korn Shell
(ksh) to gain root privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/ksh_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29741");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (aix_check_ifix(release:"7.2", ml:"03", sp:"05", patch:"IJ32285s4a", package:"bos.rte.shell", minfilesetver:"7.2.3.0", maxfilesetver:"7.2.3.20") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"03", sp:"06", patch:"IJ32285s4a", package:"bos.rte.shell", minfilesetver:"7.2.3.0", maxfilesetver:"7.2.3.20") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"03", sp:"07", patch:"IJ32285s4a", package:"bos.rte.shell", minfilesetver:"7.2.3.0", maxfilesetver:"7.2.3.20") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
