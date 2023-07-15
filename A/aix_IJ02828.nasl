#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory aixbase_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(106689);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2018-1383");

  script_name(english:"AIX 7.2 TL 1 : aixbase (IJ02828)");
  script_summary(english:"Check for APAR IJ02828");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1383
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1383 A
software logic bug creates a vulnerability in an AIX 6.1, 7.1, and 7.2
daemon which could allow a user with root privileges on one system, to
obtain root access on another machine."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/aixbase_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");
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

if (aix_check_ifix(release:"7.2", ml:"01", sp:"01", patch:"IJ02828s1a", package:"bos.cluster.rte", minfilesetver:"7.2.1.0", maxfilesetver:"7.2.1.2") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"01", sp:"02", patch:"IJ02828s2a", package:"bos.cluster.rte", minfilesetver:"7.2.1.0", maxfilesetver:"7.2.1.2") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"01", sp:"03", patch:"IJ02828s3a", package:"bos.cluster.rte", minfilesetver:"7.2.1.0", maxfilesetver:"7.2.1.2") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
