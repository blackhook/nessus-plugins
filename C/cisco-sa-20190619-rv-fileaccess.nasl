#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126005);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_cve_id("CVE-2019-1898");
  script_xref(name:"TRA", value:"TRA-2019-29");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo65034");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo65037");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo65038");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190619-rv-fileaccess");

  script_name(english:"Cisco RV110W, RV130W, and RV215W Routers Syslog HTTP Access Information Disclosure Vulnerability (cisco-sa-20190619-rv-fileaccess)");
  script_summary(english:"Checks router version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of the Cisco
Small Business Wireless-N VPN Router installed on the remote host is
affected by an information disclosure vulnerability. An
unauthenticated, remote attacker can exploit this to disclose 
potentially sensitive information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?911b7007");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2019-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20190619-rv-fileaccess.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv110w_wireless-n_vpn_firewall");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv130w_wireless-n_multifunction_vpn_router");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv215w_wireless-n_vpn_router");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('cisco_func.inc');

device = get_kb_item_or_exit('Cisco/Small_Business_Router/Model');
version = get_kb_item_or_exit('Cisco/Small_Business_Router/Version');

if (device =~ "^RV110W")
{
  fix = '1.2.2.4';
  bug = 'CSCvo65037';
}
else if (device =~ "^RV130W")
{
  fix = '1.0.3.51';
  bug = 'CSCvo65034';
}
else if (device =~ "^RV215W")
{
  fix = '1.3.1.4';
  bug = 'CSCvo65038';
}
else
  audit(AUDIT_HOST_NOT, 'an RV110W, RV130W, or RV215W router');

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0 )
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ' + device + ' router', version);

report =
  '\n  Bug               : ' + bug +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix;
security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
