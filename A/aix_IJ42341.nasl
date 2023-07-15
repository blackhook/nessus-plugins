#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory libxml2_advisory3.asc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(165285);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id("CVE-2022-29824");

  script_name(english:"AIX 7.3 TL 0 : libxml2 (IJ42341)");
  script_summary(english:"Check for APAR IJ42341");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29824
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29824 GNOME
libxml2 is vulnerable to a denial of service, caused by an integer
overflows in several buffer handling functions in buf.c (xmlBuf*) and
tree.c (xmlBuffer*). By persuading a victim to open a
specially-crafted XML file, a remote attacker could exploit this
vulnerability to cause a denial of service condition."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/libxml2_advisory3.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29824");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

var aix_report_extra;
var flag = 0;

if (aix_check_ifix(release:"7.3", ml:"00", sp:"01", patch:"(IJ42341s2a|IJ45059m2a)", package:"bos.rte.control", minfilesetver:"7.3.0.0", maxfilesetver:"7.3.0.1") < 0) flag++;
if (aix_check_ifix(release:"7.3", ml:"00", sp:"02", patch:"(IJ42341s2a|IJ45059m2a)", package:"bos.rte.control", minfilesetver:"7.3.0.0", maxfilesetver:"7.3.0.1") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
