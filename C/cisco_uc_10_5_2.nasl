#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103112);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12212");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf25345");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170906-cuc");

  script_name(english:"Cisco Unity Connection Reflected XSS Vulnerability (cisco-sa-20170906-cuc)");
  script_summary(english:"Checks Cisco Unity Connection version");

  script_set_attribute(attribute:"synopsis", value:
"The version of Cisco Unity Connection on the remote host is affected
 by a relfected cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"Cisco Unity Connection 10.5(2) with a default configuration allows 
remote attackers to conduct a reflected cross-site scripting (XSS) 
attack against the user of the web interface by submitting 
invalid input parameters via HTTP GET or POST.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170906-cuc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86fa5dd5");
  script_set_attribute(attribute:"solution", value:
"Upgrade Cisco Unity Connection per the vendor advisory CSCvf25345.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("Host/Cisco/Unity_Connection/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item("Host/Cisco/Unity_Connection/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, 'Cisco Unity Connection');
fix = "10.5.2.16130.1";
if (version =~ "^10\.5(\.|$)")
{
  if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + 
      '\n';
    security_report_v4(severity:SECURITY_WARNING, extra:report, port:0, xss:TRUE);
  }
  else audit(AUDIT_INST_VER_NOT_VULN, "Cisco Unity Connection", version);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco Unity Connection", version);
