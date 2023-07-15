#TRUSTED a74549b0a02e3eeb8b236ac9a004e25f353c7ca67a85c1e7708a49ddff6181ed6f5276733babbdd1c9135372d2f024cfee37089eb23194b357afa8f3d2b57ca1b83640503e51467442cd2137281aed07662fcc4b68e0f37d4059a1f0ca829f02326ff8607bf8bb4ec3dd9b6789e943a045bfc97fd352c799ee4afd8d06721bb36feb79792f9a4c6c87a1488cd9bc36195e6b4daf3497b59f0ee01e8c6411aca362eacfa0cc941707d0f325dcbb065d57c447c7b0769f9d99d14cf108fa34922d6b6067e1034f8924986e214aa247110154b8dc7ea3d32ea3bec7abd007b76420016dd659195bc1030bc5d384ce7d97c6afaa7e55276b11d58d032e3a0480a736650a350ea8bf54f9704daccbf5be5d7e2046521eba7f883e78388a4c771c4a010f4a82a0488922bed66cb7b248847a03886c0437f69b9cc97655ba4cb3468400ba6768b5d6a15a288e9358a30ecfea69728c96dd0b628e7d6e0263bb46c86eb62ce1df97ed46cdf61063d33cb2842be7ceba218d5eae0515b6cbb2139e8748328753b42377475a0a0597c755f032f703bcfc82cd7835288918f5cfbd15a0532cd6157f76fc86ac823e8cdd0b5f6574a54ca49199be97ec0e0ce335a2f45574f9a5fbc4538c2c7999836c5efb3568e156f780bc94955fbcb0535513a9d48a3d80fa0e8fdca27848230ea5876014f0b826cdfab0f44e729947d88130a84bebdebb
#TRUST-RSA-SHA256 7e881b35dadc067c703df8f7ae817bd827003fa0d9d0b55c0fc2f1213c4b651d63d7462915a888f4387d04869ca3692ce9a74d36333948abf13e9ddadf9db1c972b85f5eb3c28e4fe9f9b8e355166086f53fcef6a65a3f10d6e56316bf84601cb09c73749aa0d5f5c6ed1306068f8951ba760b51f09b0bedffcec086638af4a85e9b2c92411dda4250c03529b30deef134919a995d31cb95451d3a31ef992df7aef096eaaac6385c3aa633d5a34877cb2e74a6bbff0a802db1b0173b035b247eda1c1f1fe06b7fd20fb470f47c4f32d3dca3c3ba070fcad55df1b2cb673669f745da5916fb5b9e74bc1d28bcf7953e086bd80ec217b111d6d4fb47459a09d5f5c179c3a1d1a686d28453f4842c1579fb08bac25db5642ff064cdcdf173d6a05fe36353aae81936299a52f5d4205b6e8ec8db8f453fe390296e3d97e23179051be2a04bb3fbaa2f80ac0a01e3a1a6956bb8d5299cc490f23423bed635d7583c874341796367181f3e8d6f5135b9f2d9386538e6273c2ef47413bedcec27a5fff8ce3235e5baff44084add32317e0e94f24cbd7a3032ff400fc32b5617cc4a2324cc04f76c49948ec8fbd7b4a0cbb43c79654abde5e6748fb0d97b8a32ab64bb74cc2f10af0f003f7512fb1b6979c987121a8e94f742007fa2b2700ac007f7a13f05e785a67002fc3e3f6aa4a77c26c7c4b7f3283e5acbb02ba6a811aba16a19ec
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136918);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3188");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo31790");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-mgmt-interface-dos-FkG4MuTU");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software Management Interface DoS (cisco-sa-ftd-mgmt-interface-dos-FkG4MuTU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a denial of service
(DoS) vulnerability in the management interface due to how FTD handles session timeouts for management connections. An
unauthenticated, remote attacker can exploit this issue, by sending a large and sustained number of crafted remote
management connections to an affected device, to cause the remote management interface or Cisco Firepower Device Manager
(FDM) to stop responding.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-mgmt-interface-dos-FkG4MuTU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b75ff2a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo31790");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo31790.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',   'fix_ver': '6.4.0.9'},
  {'min_ver' : '6.5.0', 'fix_ver': '6.5.0.5'}
];

# Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes.
expert = get_kb_item("Host/Cisco/FTD_CLI/1/expert");

# This plugin needs a hotfix check. If we havent successfully run expert to gather these, we should require paranoia.
if (!expert)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  extra = 'Note that Nessus was unable to check for hotfixes';
}
else
{
  # For 6.5.0, advisory specifies the hotfix name "and later", so ver_compare is TRUE
  hotfixes['6.5.0'] = {'hotfix' : 'Hotfix_H-6.5.0.5-2', 'ver_compare' : TRUE};
}


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo31790',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
