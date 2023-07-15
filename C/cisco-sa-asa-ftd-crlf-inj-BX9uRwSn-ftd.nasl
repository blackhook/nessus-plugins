#TRUSTED 4b4520c81f78b9fecff1d2127c1d3a6948425db375dec8fb1169f35dbc3f4246fa62f20d13751b33dca226da1c8554d40f19835e08c2961962bcc55986942fd7f6e9049b69719f43a825c81140a05e2d3d2ac10867acc4a39fa1ddaa92c6b777d89374707f2248bd66c5ba4476bb89e7086573ac849a39d0d96b9b20cb7e1db8fe4748963eaf465f47617b3d03bba88044a298e8f88001673821511031d4286b97c2adddeaa3af8cc9e492edcbf435961a393d8a832a5b7b92f290784aeda3b5ed7a689c3c45cb8b784d7eaa33c7e656eb77a89ecd7eeb3163baa76386e38ab878849c511bf40eff8b88dce6579c65b938d6d4ec58150ceb8a52657669cfa996e77a0e2cbb864364bd41e3a3b01c079f22ce006ce4234b759a2b84230b442b35a5c92b4990efe20dccb01eac6564a3fd3e6d2bec69f8dd5443940227e9cfc3ef8f73571ca6b39a444be32e2217902463655d4e3e29968e0fc508538b53a4be51da7d087cb926e9f0e120de192974e2683c8204d87653e86f439ade851d7578bc7eb164a6a32d17a2839a17c9a550448988363719d738788dfc37c2a60fad612d755a1dba88511704fe83cd35d3dbacbea2d9bdb7575eedd55befb73a67468928c95ee88120c5810ea3e3ca6ba020d6b0d389e557b9135b328121bd2983f404dcd0f613334d94ed31f56f997c23f4d2062c78d028e0ca431345af17f086d87731
#TRUST-RSA-SHA256 2c848595cdf5ee5530ac05a0099098c82e5c301d9db2710cb6eae04c49a247c48fee509aa1efb8ceff37241ec72ea35585dad5e319c0b5ef11885b91326bb8ed492a5961f83fa69fada41c97d2876ef94f0f7beeb5ad25944206001439125c0075cdb2c4f9628747e2f2223d33565de369dea0726dcea34405338074dded72bf004f2ead174d7a20147d675037802989b5f7476b37e440ee9f53eb2209eeeaf4e987eb9b96b7bf714bc84721bdf4d5840caca8cd0b3d3e347fb0bafa5f2ca61f86af09d9d35e9000dc864388879815d1e7950f8a8813647665e5611d96e60727ca5829329317ca92257d8d5d72eb3c31b419c97f7ab05976fae806bc0de424eabe4df46fee299152941ed49ccb52d9229c08e149486160307e46a7960b4d762be0504c32f094618b161c3b196a51ac5e86dc7d1c164c855c58a5cd159fb77f025d468dfe7a2384de29bcf0665d9e0f402327393df5f87fee56777a0b91213f22a614c399e253ed53fdd30caca55c2bdc405cc17e214b5a4fd520772c3b951ca40f28c2efa1c0c9b29855f0330d0a208dadba560251a8a0d581468fd6ad4e6e908b5b60b599d325658cc0e294c92375ce26dbcb066cf63f2fcf8fca868a3648c1f905f27c74ffa4dda00ea4b7021322329d93e532b4ecec3790e60b8b2943afff8d2af1c5e31e773b9abf8d8e2bd381ad130062b9998db149fa8eed85aba98af4
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149525);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3561");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt18028");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-crlf-inj-BX9uRwSn");

  script_name(english:"Cisco Firepower Threat Defense Software WebVPN CRLF Injection (cisco-sa-asa-ftd-crlf-inj-BX9uRwSn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Clientless SSL VPN (WebVPN) of Cisco Firepower Threat Defense (FTD) 
Software is affected by an CRLF injection vulnerability due to improper input sanitization. An unauthenticated, 
remote attacker can exploit this by persuading a user of the interface to click a crafted link which could allow the 
attacker to conduct a CRLF injection attack, adding arbitrary HTTP headers in the responses of the system and 
redirecting the user to arbitrary websites.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-crlf-inj-BX9uRwSn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f487e64d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt18028");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt18028");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3561");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(93);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '6.3.0.6'},
  {'min_ver' : '6.4.0',  'fix_ver' : '6.4.0.10'},
  {'min_ver' : '6.5.0',  'fix_ver' : '6.5.0.5'},
  {'min_ver' : '6.6.0',  'fix_ver' : '6.6.1'}
];

var workarounds = make_list();
var workaround_params = '';
var cmds = make_list();
var extra = '';

var is_ftd_cli = get_kb_item_or_exit('Host/Cisco/Firepower/is_ftd_cli');
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');
    
  workarounds = make_list();
  extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn'], CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['vpn_load_balancing_enabled'];
  cmds = make_list('show running-config', 'show vpn load-balancing');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt18028',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  require_all_workarounds:TRUE
);
