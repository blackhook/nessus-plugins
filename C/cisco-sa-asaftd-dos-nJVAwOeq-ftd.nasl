#TRUSTED 17b2bfe6a6844569a34f334014dccfa6b2e7a374ab34a18afd93ad4ef3e959218afbbbfd7f997a655df840dc6d66065fff57183bd33e66123b5a3957dfe5de5b7e956a1bfd2dbe964de1e5acd1b2e6b4443d42a25ee73e3e4036bb469ed3379e6cb16352593fa8e4842a039c24ab65aba175f7ee2ecc7697ac57935951d98d07fd6e0846353cc57799258827d38b24d5b496c4a0e0a4479d72f253bc7de9e3dddfce9eb1600e687abafb613394179179b0caefaf6effeb608ec4c78e24e1f0ec71c6c7fb95fb1dde0ac210defe116e47431c3961895b1ff6812663ce818b62be7995c55356ab3bb3de28643a1bc83ce891043a33da9415c4522199a914184f9c57c48aa99864defc503a9e421c074b9eca765d6002454fbc14ba3447a1357e5fa953c6467c55948679b5a201a7b39780b9fdc4993747c4b891848479f224bcbee4471dc13dd96311fe471116cc27c6f074eb8304034bbc0df3378d403d2968d314743fde5a475fcb5412b4bb497f2b221891398fdbff2fcb37ddc2f0bf4a6e76a9b79ef95f7e47b7f2e4a63f30daf43d950c2e1ae16682ce8d989363d0483cd07f619273bc9924ef508d730f95b5929886da54414e7b37af868ebd5b37d982707d5369d165bd2cf88eae623bbac0918e372eb17d0287f55531e9daa6c019579f96302783b0764548ad649ad3a21a3daa5969786d55ee80d643cc9dcc7de54549
#TRUST-RSA-SHA256 276b2cfd42e898e381492e0354a601c64c2f9303002af1d3c5cab546378102215ebe4987551c4b11e00e77bd96152daa9ba4bef9d1398eb6b7c1e354c475f96ea8f9e1ffe6dea8c7471ba02724a73773c8f1e0ae2c3e70c2dfe4fba3e2b233f15d77b849c4847ff136e96242c05f3d392be380774b193cc98917da391da566729fd44f0dce45fd2e449e8e232efe9f871615c10c168f4578c3073879ff631642c788c13948212b38650f0667b4a071fb12cc76632ecbf9b676a8e86dc87af6e2b2a188a1c7ca8055122f49497855c6991288e5ab49900781e2a7bc9f2a637c822a2ce6a8208c78460bde860aa0536abc06bdefcb2053cfa8e4f64a89345ba5b7f067843e0237ffe27127984ddd92e4590f70917fedb7307d7c641636ed65c9fd88507f940a79600cdd0c1197613d5e79a82b41fea6d5a4220d311e5ca965523dcfab9e42776592d0514b78962ba9f2f0b3997d980d6660847811ac01c28d6ce47b2cc4b3d8f41259ad33b54de79ebf477adf36881ad439e021752f828938176ca77981035956cf481b6fa1687f766b4c01f05fd42ca89e3ccef6c103e82407954d5af152794e6f767e1e314e9f7a782db9f34bfc751bbb8f04c125bb4dd137ffce7c89044ed4169f05ec9ddd305f91b88cfda529c0086e280204d85a8c2de2f2fa3810593fc374d19e3b7ae09f636a2cdb47e59eb095582879586c317908aaae
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161263);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20760");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz76966");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-nJVAwOeq");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Firepower Threat Defense Software DNS Inspection DoS (cisco-sa-asaftd-dos-nJVAwOeq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the DNS inspection handler of Firepower Threat Defense (FTD) Software could allow an unauthenticated,
remote attacker to cause a denial of service condition (DoS) on an affected device. This vulnerability is due to a lack
of proper processing of incoming requests. An attacker could exploit this vulnerability by sending crafted DNS requests
at a high rate to an affected device. A successful exploit could allow the attacker to cause the device to stop responding,
resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-nJVAwOeq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28fef957");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz76966");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz76966");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.15'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.2'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.4'},
  {'min_ver': '7.0.0', 'fix_ver': '7.0.2'},
  {'min_ver': '7.1.0', 'fix_ver': '7.1.0.1'}
];

var hotfixes = [];

# This plugin needs a hotfix check if it is 6.7.0.x. If we havent successfully run expert to gather these, we should require paranoia.
if (product_info['version'] =~ "^6.7.0.")
{
  # Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes.
  var expert = get_kb_item('Host/Cisco/FTD_CLI/1/expert');

  if (!expert)
  {
    if (report_paranoia < 2)
      audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');
  
    var extra = 'Note that Nessus was unable to check for hotfixes';
  }
  else
  {
    hotfixes['6.7.0'] = {'hotfix' : 'Hotfix_AA-6.7.0.4-2', 'ver_compare' : FALSE };
  }
}

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['dns_inspection'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz76966',
  'cmds'     , make_list('show running-config policy-map'),
  'extra'    , extra
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
