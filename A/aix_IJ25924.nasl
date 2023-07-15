#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory17.asc.
#

include('compat.inc');

if (description)
{
  script_id(139752);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617");

  script_name(english:"AIX 7.1 TL 5 : bind (IJ25924)");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8616
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8616 ISC BIND
is vulnerable to a denial of service, caused by the failure to limit
the number of fetches performed when processing referrals. By using
specially crafted referrals, a remote attacker could exploit this
vulnerability to cause the recursing server to issue a very large
number of fetches in an attempt to process the referral. ISC BIND is
vulnerable to a denial of service, caused by a logic error in code
which checks TSIG validity. A remote attacker could exploit this
vulnerability to trigger an assertion failure in tsig.c."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/bind_advisory17.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/24");
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

flag = 0;

if (aix_check_ifix(release:"7.1", ml:"05", sp:"04", patch:"IJ25924s6a", package:"bos.net.tcp.client", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.35") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"05", patch:"(IJ25924s6a|IJ29230m7a)", package:"bos.net.tcp.client", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.35") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"06", patch:"(IJ25924s6a|IJ29230m7a)", package:"bos.net.tcp.client", minfilesetver:"7.1.5.0", maxfilesetver:"7.1.5.35") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
