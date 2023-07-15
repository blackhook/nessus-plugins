#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory commonshttp_advisory.asc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(174444);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2012-5783");

  script_name(english:"AIX 7.2 TL 5 : commonshttp (IJ44994)");
  script_summary(english:"Check for APAR IJ44994");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5783
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-5783 Apache
Commons HttpClient, as used in Amazon Flexible Payments Service (FPS)
merchant Java SDK and other products, could allow a remote attacker to
conduct spoofing attacks, caused by the failure to verify that the
server hostname matches a domain name in the subject's Common Name
(CN) field of the X.509 certificate. By persuading a victim to visit a
Web site containing a specially-crafted certificate, an attacker could
exploit this vulnerability using man-in-the-middle techniques to spoof
an SSL server."
  );
  # https://aix.software.ibm.com/aix/efixes/security/commonshttp_advisory.asc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f4c6751"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (aix_check_ifix(release:"7.2", ml:"05", sp:"03", patch:"IJ44994s4a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.0", maxfilesetver:"7.2.5.1") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"03", patch:"IJ44994s4a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.100", maxfilesetver:"7.2.5.100") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"03", patch:"IJ44994s4a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.200", maxfilesetver:"7.2.5.200") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"04", patch:"IJ44994s4a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.0", maxfilesetver:"7.2.5.1") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"04", patch:"IJ44994s4a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.100", maxfilesetver:"7.2.5.100") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"04", patch:"IJ44994s4a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.200", maxfilesetver:"7.2.5.200") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"05", patch:"IJ44994s5a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.0", maxfilesetver:"7.2.5.1") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"05", patch:"IJ44994s5a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.100", maxfilesetver:"7.2.5.100") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"05", patch:"IJ44994s5a", package:"bos.ecc_client.rte", minfilesetver:"7.2.5.200", maxfilesetver:"7.2.5.200") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
