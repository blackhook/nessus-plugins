#TRUSTED 6e5823cdf3df62222f460142caf46b68228eb6a58500a9d7e2251acf922f5e6b7828e22bc4eba498789deb212c5123d76b3cc3bc59d45f96055a999968f732aa259a35859d3cd9c3b1d61c6dfdcc11a547062c2d239023a47470202e71dba4c02fb4a71d2ea6f4fdf38c054069c16aa55df8571231c4f88ae57ae36aac9183ca0bddc781ad4cecf8ed330b46d05f46782c93315498462c77eb398f991483fc5182df924c5cfe04e83ed4bdafdb0c23f6a88089d28a8001e774d3411c888b4d792b3f45d0630595aeb55f1ef5d42f72fbc40c97751ff4d3e2fd8c9b585c350ee8b321c0def021ee3c5a7c9604c5c3aecef96dbb39d181d1f96ae6dc8f5137210cc9ac3b263462dbd2aaea900ff6135e913149e46965fe6b9786babe4f5786d57d821e1e7a4a686ac5a637a43657a0f5944aae7ab3c63ca4556e5ca7f94c726fa2484ff3727120e27b1eacae479a2860bfc826f4733a78acd8d53770a63b12e52a9e6bfae9b2f0027a6b6d0395f246b272f2bc50984c9a072fa6f761305a000a79368f6fc4dc0d6f6f8f010087bc7449baa3023bd40630d16abea23963962aa5603fe74a8ed703b8ab56bdc314396032ab83b028aa649750adb5f651be78a002970256fc31b858456651abb27fb4ae78b5a386a383ce9fe878f34f810f60efa8b0ea1c2e965a2e6e9189c7458f5b7a1be8349ca38e351c36567587050ddb07b52c
#TRUST-RSA-SHA256 24f2b33268f0d2f3146dac4519da459f03f26c8402179d3c5b08c5504a881466da5fb38c91d4d4569cbffa96efa9235fb6ad30cfaacb844473e0b7a0902956ed578ec385a884d760f24c680c503a71d4684d583c55fd18dcc22100154e3eea29d13f5101f5b45a77c65406e018dbff30d92d768c4c573b85582a22bbe3eb143657d8ad9c68207890b99aa349146b269360a2ce3c805dbd377e2dbdfac974b43acb77a02f37f5de9d956b7b2d955a021b9af3cddb736021c5510e48d8c53da112d1a83a33feaaa074b4b33355f9983ec2393e5b79aacbf651a4dc1fd056678bcf8946ae97885cd78eb7c234c2ca39917bbcd9771855434d51e5124ef7ab5860bef6b89486183bdd612c975fc93b25febc6af5e9e4626ed88bb595b1cb50067f47e88b3218e95d01ed2237b2623307378f1a65ae7b4c90a116b3b82921003a86abd7652e6895add850d026dbf8b373b35bbe1ee3f110e428916ba4af771fb6470e9a2b82d66a7da36be0f2284abb446ed3a54b710921cf14d200a52388efe237ff4e79dec4505a2d5386f8a248d72b217443e178b87ac1ae52317e5c57aed03ae6a67c02d5284b36efbf82a1d14a3227681a59dec6267fddc3b07117e9392eacfee9401a852c37914356097f01bd65069285e033b129c025da2ceaad1e86511b0737c63c65da89e5702af0336195566102562482a0ff3001b586d1397f35ff8aab
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137135);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3254");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp16945");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp16949");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-mgcp-SUqB8VKH");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Adaptive Security Appliance Software DoS (cisco-sa-asaftd-mgcp-SUqB8VKH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco Adaptive Security Appliance (ASA) due to inefficient memory
  management in its Media Gateway Control Protocol (MGCP) inspection component. An unauthenticated, remote attacker can 
  exploit this issue, by sending specially crafted packets to an affected device, to cause a DoS condition.

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.

  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
  number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-mgcp-SUqB8VKH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84c4cd75");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp16945");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp16949");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '9.6.4.34'},
  {'min_ver' : '9.7',  'fix_ver': '9.8.4.7'},
  {'min_ver' : '9.9',  'fix_ver': '9.9.2.66'},
  {'min_ver' : '9.10',  'fix_ver': '9.10.1.27'},
  {'min_ver' : '9.12',  'fix_ver': '9.12.2.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['mgcp-policy-map'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp16945, CSCvp16949'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
