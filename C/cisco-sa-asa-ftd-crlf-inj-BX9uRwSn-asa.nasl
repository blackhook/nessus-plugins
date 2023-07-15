#TRUSTED 1b10d4bc8e9fbbca78223ec42f75d78fd9beaac2f2d12475f1c592024daef66bd71f0ab8cf4f5daca631158089fd4b6c161ddaf88d53e50cadbcb3ef7c81665ab7e561df271d2e7c70d236da5c232f4eb38bc483d91e501b0e446ef1a5735804e29db7d0a72b512d8e9103452b6351368a5156b871afe3b9e173490ba67446f76db7dfb2acb3eb089925f821561c50ae9d31d2f5c2957225f12686a25998254679df428043366b81af74730da3d88362c47cdbf4f2bda6b15ac4fe1c58d2d9f46345f97d00e1e0ba53f2c67d5699776982c1d7929244e1c3ee8a836481f8303587fa7cee92da00b236d79497c355d5c22469525d5160ee918d50a7d7cd959fe54e5654a58260a876a21ac3885766eb4085586f1200367bdabc32fe8c1680c39eb270a9a335cbaec9ee2fd921b9b780ab5488e8a36227394207be23a076180c6c6ca72b9f3c0884ccf04a9197d3e6e8dca472fe46a2b24370da7f4ecbf457a1eb8fa8434bd56be1022e7294f13fa74e5552f1dddd8a51f5db0d6f61f52050e78551b5e5f069fd82e784046ae65e8ada5c0d6851d4807443b6ac45107e4bc34b52483d10f145b45156e6ce809dda049ffcf7161869b73b9b2126ea79aa9040a94c27009732fe668c74a46ed5fae349f73bffc5ac874dc0c65c465da9f3ca8d91131597f3664021a07b4137c1630c866b49d6bbd45eecfcced8581e510264a4b387
#TRUST-RSA-SHA256 9cb1a7715fdf30626a5ca98440d025646655b90e1195b6e894de68e9b6e3c85215e374c02d51e509085bc8c2908b00eaffd0a18ecc11e5224cfbafcc10fbdc4f841b9718e292aed79e2426978bb2ca5ceb749d3f2755882f507e501f692cf977d7c03f8c90938400fefd291433641427a1abc6b93a888a4c2f6ca00262408a755702bc7bd4f026eb657389323561314d8233ae50383b3e5b0cd9a5d0c37d2d8f94ce4df525665336ea0f8c864dcc4324f3e0042cf8391b036cf66a3c060b3a7ffb04a64bcc492697a9aacace5fa698e22c2909ac2b1bca7cdc2539b0ccd8e6c893653a3443a5c0f35477e5ac16a7846242953cbbc8fc2fd7b4faad845e70bebf5d27bb8f7a8d457e1d0af06ccd64e9e0f4c242119eb1c57763b94964151a60c31e740e9d317940a821c9a879429500b39aafcf04ff0b8ebea16ad815496b1a258d081f58aa4d3d35ec9983c01ed1daaee08930750181b6733cb59b204a10e0afb4147c1dc0ea3601ebceb600956e765342838184d6449d4229f8e5ca6b667389766e6b24ca020fe8c5ec4656503de2e1818ed9508f6d30c51bf99c22ed948532dda7df3634796d888ba4a3b399470855377aea2e1bf9f7f6b664a8f7d4a2a0a917b3215e2648fac18acd9c15418a1ae3d4b2c371cfe1f3bb7e6af321689a32b4c3f69b953255c0bdb557b9c0a48142b86cafc08e1e3fbe9fa6498b5a16279de9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149526);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3561");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt18028");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-crlf-inj-BX9uRwSn");

  script_name(english:"Cisco Adaptive Security Appliance Software WebVPN CRLF Injection (cisco-sa-asa-ftd-crlf-inj-BX9uRwSn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Clientless SSL VPN (WebVPN) of Cisco Adaptive Security Appliance (ASA) 
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.6.4.35'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.20'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.80'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.43'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.3.9'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.10'},
  {'min_ver' : '9.14',  'fix_ver' : '9.14.1.10'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn'], CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['vpn_load_balancing_enabled'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt18028',
  'cmds'     , make_list('show running-config', 'show vpn load-balancing')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  require_all_workarounds:TRUE
);