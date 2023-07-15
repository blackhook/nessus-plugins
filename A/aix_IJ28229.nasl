#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory power9_advisory.asc.
#

include('compat.inc');

if (description)
{
  script_id(143142);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");
  script_cve_id("CVE-2020-4788");
  script_name(english:"AIX 7.1 TL 5 : power9 (IJ28229)");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM Power9 processors could allow a local user to obtain sensitive information 
from the data in the L1 cache under extenuating circumstances. (CVE-2020-4788)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/power9_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4788");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version", "Host/AIX/processor");

  exit(0);
}

include('aix.inc');

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);
if ( ! get_kb_item("Host/AIX/processor") ) audit(AUDIT_UNKNOWN_ARCH);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

# Exit if the host does not have a Power9 processor
var arch = get_kb_item('Host/AIX/processor');
if ( 'power9' >!< tolower(arch) ) 
exit(0, 'The remote AIX host does not have a Power9 processor, and is therefor not affected by this vulnerability');

var flag = 0;

if (aix_check_ifix(release:"7.1", ml:"05", sp:"05", patch:"(IJ28229s5a|IJ28825m5a)", package:"bos.mp64", minfilesetver:"7.1.5.35", maxfilesetver:"7.1.5.35") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"05", patch:"(IJ28229s5b|IJ28825m5b)", package:"bos.mp64", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.34") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"06", patch:"(IJ28229s6a|IJ28825m6a|IJ33318m6a)", package:"bos.mp64", minfilesetver:"7.1.5.38", maxfilesetver:"7.1.5.38") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"06", patch:"(IJ28229s6b|IJ28825m6b)", package:"bos.mp64", minfilesetver:"7.1.5.37", maxfilesetver:"7.1.5.37") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"06", patch:"(IJ28229s6c|IJ28825m6c)", package:"bos.mp64", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.36") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"07", patch:"(IJ28229s7a|IJ28825m7a|IJ33318m7a)", package:"bos.mp64", minfilesetver:"7.1.5.40", maxfilesetver:"7.1.5.40") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"07", patch:"(IJ28229s7b|IJ28825m7b)", package:"bos.mp64", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.39") < 0) flag++;

var aix_report_extra;
if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  if (report_verbosity > 0) security_report_v4(port:0, severity:SECURITY_NOTE, extra:aix_report_get());
  else security_report_v4(port:0, severity:SECURITY_NOTE);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
