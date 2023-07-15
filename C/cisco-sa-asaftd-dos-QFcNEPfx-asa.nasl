#TRUSTED 54a18b47cdeb899df4a5a75af54004aec6a8bd53a02f880904732a69532e127c31425942180967922491a1bcefe02e63b80327369512ee689ba7e57ecf0a2d7d9579d7e8a8358edcb130c743146f6b3e3ec07316c7304eefc28589fde3ad05d39c770526b38153dbe9d602f45f77bb065aa264bc239fae8ac3c5d205accea0bfde5191d1e6cb3827c7b597fdf3a5a5118fcd2797e03d71b49df4cb8a7d179058a28e310543caee8e4adac1e41d56978545bbac57e40ea64c97d9ff8087f37e513c52ab9b79f80a25759853bebe37c42c059dc053e8b4956a762d186994233786d4dd5af3f22b2c2e18106a6cd08dc040e3179dbf094bdc88cbe0bfc31bbbee515d64a33b5b9540ba5ee8c1d8c1bb755d096f5e58c0b9d1d38ded4219b45118527f54ec95b67510eff0a205418f7f14ccc2be4cf365097424bd39d55eae23f24bb37ac5853285f88a5218721b2446e0f9ac69ae7827bbcfd57bf477b72bf8420ca2af6bdc81771ccac3c7925cbc3efdbeb7e5077997691c39c798f93d27373533d35e526fd66d8ca9efb177303824622f8990bdbd6b49181659061f72fc4f362a4ede05779e456e3b2981a472964902ebfb098b569d08d486675b5e1179ecfce3129160b7121e4ca65a80c8e04bcca1400b4aeb4ce131dff0d46b4503517d8874e3374ca02355537f5ad5c7105fa22ed3ec3620ea9673f946582164f8e021c27b
#TRUST-RSA-SHA256 7bfd987add158e7f332f0efdbf579d12158d141aab1e32cbe0a08f984e43b5b0cf2ff7ff4e0c0568286a3cb634661ada60a9b3a48b4a25ba556c826373efb79328ace3d8559c910291d821741cc781044efd57e0cad63aa8da4f7693fbf8561aeeafe72fa487f96604dff5a46683100f175a12894973c39fe8d80d3f71cf76701a3e82bb41330cc4627194a154587b8cf751e04f63a811cfcc8708b622cb68d5f102fa22c0d3132356161a2f7e702b3e68fe9ee2a4836ac4732c0e8b1ce803a2cdf7007e54e4f895c5c76305e9086ad83ca199f189826e4775a0c1ed95fdde946130c88db4331c91f511f0219c355b3d01bdac24d95ee7a2f64f7c1f87dad0fa8d75844e1bf7648abaa7ca3b0445586e3249ab040f4e23977d79a92621374c395cd8fe4c546d7d2416c0612e5cc6db92460b6b9144439448e886310e59602b2520c1edaf8ec49a07b076419cf61e9768f5b97dd48fcb5b8c38f791efd95ad8e40282e60c7bc08bb4f4445ad87c62d1d88a192d81a311e3acf8771b843202dc03dcb95b89620d81020e473c4743db2f86969a9e4319849b571ab51a748b3046beceb0b75d21c7ab12683f96880d0d92611e7581d437145d59a1d4ccd546bde01f48de5347a52dbebe2cd91db2260e450b97581d22e4ab9f3f478197f40e52f34171d7db24ebbd2d79303682f519cc8986f0f7654ece1a8e03c935d06faaeea7cd
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149312);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3554");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt35897");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-QFcNEPfx");

  script_name(english:"Cisco Adaptive Security Appliance Software DoS (cisco-sa-asaftd-dos-QFcNEPfx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the TCP packet processing of Cisco Adaptive Security Appliance Software 
is affected by denial of service vulnerability due to a memory exhaustion condition. An unauthenticated, remote 
attacker can exploit this by sending a high rate of crafted TCP traffic through an affected device. A successful 
exploit could allow the attacker to exhaust device resources, resulting in a DoS condition for traffic transiting 
the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-QFcNEPfx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e0b20a5");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt35897");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt35897");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3554");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver' : '9.12',  'fix_ver' : '9.12.4.3'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.13'},
  {'min_ver' : '9.14',  'fix_ver' : '9.14.1.30'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['fragment_reassembly'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt35897',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
