#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory21.asc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(173297);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2021-25220");

  script_name(english:"AIX 7.1 TL 5 : bind (IJ40617)");
  script_summary(english:"Check for APAR IJ40617");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25220
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25220 ISC BIND
could allow a remote attacker to bypass security restrictions, caused
by an error when using DNS forwarders. An attacker could exploit this
vulnerability to poison the cache with incorrect records leading to
queries being made to the wrong servers, which might also result in
false information being returned to clients."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/bind_advisory21.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25220");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/23");
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

if (aix_check_ifix(release:"7.1", ml:"05", sp:"07", patch:"IJ40617m9b", package:"bos.net.tcp.server", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.35") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"07", patch:"IJ40617m9b", package:"bos.net.tcp.client", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.40") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"08", patch:"IJ40617m9b", package:"bos.net.tcp.server", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.35") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"08", patch:"IJ40617m9b", package:"bos.net.tcp.client", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.40") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"09", patch:"IJ40617m9b", package:"bos.net.tcp.server", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.35") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"09", patch:"IJ40617m9b", package:"bos.net.tcp.client", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.40") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
