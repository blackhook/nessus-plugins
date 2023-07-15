#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory kernel_advisory5.asc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(168771);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2022-39164", "CVE-2022-39165", "CVE-2022-40233", "CVE-2022-43380", "CVE-2022-43848", "CVE-2022-43849");

  script_name(english:"AIX 7.2 TL 5 : kernel (IJ44115)");
  script_summary(english:"Check for APAR IJ44115");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-39164
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-39164 IBM AIX
could allow a non-privileged local user to exploit a vulnerability in
the AIX kernel to obtain root privileges. IBM AIX could allow a
non-privileged local user to exploit a vulnerability in the AIX NFS
kernel extension to cause a denial of service. IBM AIX could allow a
non-privileged local user to exploit a vulnerability in the AIX TCP/IP
kernel extension to cause a denial of service. IBM AIX could allow a
non-privileged local user to exploit a vulnerability in CAA to cause a
denial of service. IBM AIX could allow a non-privileged local user to
exploit a vulnerability in the AIX perfstat kernel extension to cause
a denial of service. IBM AIX could allow a non-privileged local user
to exploit a vulnerability in the AIX pfcdd kernel extension to cause
a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/kernel_advisory5.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43849");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (aix_check_ifix(release:"7.2", ml:"05", sp:"02", patch:"IJ44115m2a", package:"bos.cluster.rte", minfilesetver:"7.2.5.0", maxfilesetver:"7.2.5.2") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"05", sp:"02", patch:"IJ44115m2a", package:"bos.cluster.rte", minfilesetver:"7.2.5.100", maxfilesetver:"7.2.5.102") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
