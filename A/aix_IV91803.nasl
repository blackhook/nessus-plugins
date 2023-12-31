#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory8.asc.
#
# @DEPRECATED@
#
# Disabled on 2017/07/20. Deprecated by aix_ntp_v3_advisory8.nasl.

include("compat.inc");

if (description)
{
  script_id(97131);
  script_version("3.8");
  script_cvs_date("Date: 2018/07/20  0:18:51");

  script_cve_id("CVE-2016-7427", "CVE-2016-7428", "CVE-2016-9310", "CVE-2016-9311");

  script_name(english:"AIX 6.1 TL 9 : ntp (IV91803) (deprecated)");
  script_summary(english:"Check for APAR IV91803");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NTPv3 and NTPv4 are vulnerable to :

http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7427 NTP is
vulnerable to a denial of service, caused by an error in broadcast
mode replay prevention functionality. By sending specially crafted NTP
packets, a local attacker could exploit this vulnerability to cause a
denial of service. NTP is vulnerable to a denial of service, caused by
an error in broadcast mode poll interval enforcement functionality. By
sending specially crafted NTP packets, a remote attacker from within
the local network could exploit this vulnerability to cause a denial
of service. NTP is vulnerable to a denial of service, caused by an
error in the control mode (mode 6) functionality. By sending specially
crafted control mode packets, a remote attacker could exploit this
vulnerability to obtain sensitive information and cause the
application to crash. NTP is vulnerable to a denial of service, caused
by a NULL pointer dereference when trap service has been enabled. By
sending specially crafted packets, a remote attacker could exploit
this vulnerability to cause the application to crash.

This plugin has been deprecated to better accommodate iFix
supersedence with replacement plugin aix_ntp_v3_advisory8.nasl (plugin
id 102129)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory8.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use aix_ntp_v3_advisory8.nasl (plugin ID 102129) instead.");

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"6.1", ml:"09", sp:"06", patch:"IV91803m6a", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.200") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"07", patch:"IV91803m6a", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.200") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"08", patch:"IV91803m6a", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.200") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
