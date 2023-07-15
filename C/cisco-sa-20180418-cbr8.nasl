#TRUSTED 84fbf6b992e7d939dc8478ab16271176cc2cbfce713dd1542db9a2e8a797e30d3a94f57d56488e0a4b1c61a831a807a33d20d942143e52e8ef39a7672f37dc0f71ac5b7cf9f682512f70ca357fd8cad46da8f6ba1bfe69c5ad1b10fecf0c6e9fda1cffe2c52b8be21901a8fad6f1f3f864868309c61991b33793d019ab8c108f82333088ac0d2d7b604c4b7951257f4acd8071e60482d14598a9f123e22eb8cf25f3ca84bd9535f3ee4658ca406d00c3a1fd2f87720915174e0baaa95223253bf967d95b9d5c86b3d3172c4eebf84ab13f5a03ea7c63f9c81fa803e0d5e5fcc207bc12bdd37d81db57b25a90c3d3983b06d8d8a8d2441c8b85d5dff7ff939e00494e97a0596e8011d3972da490c4ac0eff6c58ed6f14682da94c016da627e5230ddd6f2d2d9b5ad6ba24ea3f622cb8f815190858309fbdc69b533e4d4c48fad1d92e60876fa37266acffddee675ff8730c6e5b7981f5978aac1b3c18f67d313a8486dc9e440ef694db4a06f07754850181f54136eff8e0e2eccb722d4f0b5e779e86754d68070b403e3e31b5c2990fded53b5e7cdc35c3538586b77829b67c31cfa3c961372ae0b0773f53fa347903eaf68583b297abcb88613635f1bd1e7cccd8adcebd686ba746a58308e8156f988ba3807e7ab76775a08a1fa28646c81955ddf4ae0a9dad1d2c9f7d89ed35ceff3bb10605956528ac51306e4060e38d4635
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132043);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0257");
  script_bugtraq_id(103948);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg73687");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-cbr8");

  script_name(english:"Cisco cBR Series Converged Broadband Routers High CPU Usage DoS (cisco-sa-20180418-cbr8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability on
Cisco cBR Series Converged Broadband Routers due to incorrect handling of certain DHCP packets. An unauthenticated,
adjacent, attacker can exploit this, by sending certain DHCP packets to a specific segment of an affected device in
order to increase CPU usage and cause a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-cbr8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b49f808");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg73687");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvg73687.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
if (model !~ 'cBR')
  audit(AUDIT_HOST_NOT, 'an affected model');

version = product_info['version'];
if ('SP' >< version)
  vuln_ranges = [
    { 'min_ver' : '3.18', 'fix_ver' : '3.18.3bSP' }
  ];
else
 vuln_ranges = [
    { 'min_ver' : '16.4', 'fix_ver' : '16.6.3' },
    { 'min_ver' : '16.7', 'fix_ver' : '16.7.2' }
  ];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , version,
  'bug_id'   , 'CSCvg73687'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  router_only:TRUE
);
