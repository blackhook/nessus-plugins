#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory trace_advisory.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150804);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");
  script_cve_id("CVE-2021-29706");
  script_name(english:"AIX 7.1 TL 5 : trace (IJ32940)");
  script_summary(english:"Check for APAR IJ32940");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM AIX could allow a non-privileged local user to exploit a vulnerability in the trace 
facility to expose sensitive information or cause a denial of service. (CVE-2021-29706)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/trace_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4887");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include('aix.inc');

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

var flag = 0;

if (aix_check_ifix(release:"7.1", ml:"05", sp:"06", patch:"(IJ32940m6a|IJ33318m6a)", package:"bos.mp64", minfilesetver:"7.1.5.38", maxfilesetver:"7.1.5.38") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"06", patch:"IJ32940m6b", package:"bos.mp64", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.37") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"07", patch:"(IJ32940m7a|IJ33318m7a)", package:"bos.mp64", minfilesetver:"7.1.5.40", maxfilesetver:"7.1.5.40") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"07", patch:"IJ32940m7b", package:"bos.mp64", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.39") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"08", patch:"(IJ32940s8a|IJ33318m8a)", package:"bos.mp64", minfilesetver:"7.1.5.42", maxfilesetver:"7.1.5.42") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"08", patch:"IJ32940s8b", package:"bos.mp64", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.41") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_report_v4(port:0, severity:SECURITY_NOTE, extra:aix_report_get());
  else security_report_v4(port:0, severity:SECURITY_NOTE);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
