#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory sendmail_advisory3.asc.
#

include("compat.inc");

if (description)
{
  script_id(108895);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2014-3956");

  script_name(english:"AIX 7.2 TL 2 : sendmail (IJ02920)");
  script_summary(english:"Check for APAR IJ02920");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3956
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3956 The
sm_close_on_exec function in conf.c in sendmail before 8.14.9 has
arguments in the wrong order, and consequently skips setting expected
FD_CLOEXEC flags, which allows local users to access unintended
high-numbered file descriptors via a custom mail-delivery program."
  );
  # https://aix.software.ibm.com/aix/efixes/security/sendmail_advisory3.asc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d01b5208"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");
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

if (aix_check_ifix(release:"7.2", ml:"02", sp:"00", patch:"IJ02920s0a", package:"bos.net.tcp.sendmail", minfilesetver:"7.2.2.0", maxfilesetver:"7.2.2.15") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"02", sp:"01", patch:"IJ02920s0a", package:"bos.net.tcp.sendmail", minfilesetver:"7.2.2.0", maxfilesetver:"7.2.2.15") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"02", sp:"02", patch:"IJ02920s0a", package:"bos.net.tcp.sendmail", minfilesetver:"7.2.2.0", maxfilesetver:"7.2.2.15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:aix_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
