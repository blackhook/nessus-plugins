#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory freebsd_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(118825);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2018-6922");

  script_name(english:"AIX 6.1 TL 9 : freebsd (IJ09619)");
  script_summary(english:"Check for APAR IJ09619");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6922
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6922 FreeBSD
is vulnerable to a denial of service, caused by the use of an
inefficient TCP reassembly algorithm. By sending specially-crafted TCP
traffic, a remote attacker could exploit this vulnerability to consume
all available CPU resources."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/freebsd_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (aix_check_ifix(release:"6.1", ml:"09", sp:"10", patch:"IJ09619sAa", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.401") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"10", patch:"IJ09619sAa", package:"bos.perf.perfstat", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.400") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"11", patch:"IJ09619sBa", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.401") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"11", patch:"IJ09619sBa", package:"bos.perf.perfstat", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.400") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"12", patch:"IJ09619sCa", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.401") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"12", patch:"IJ09619sCa", package:"bos.perf.perfstat", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.400") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
