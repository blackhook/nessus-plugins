#TRUSTED 6d642822da66ca64b7e1dd8bfd1f20cf3a5af97afaf8aba7d90c85b669ba01850998e5a0a40aa044354ed29218bdcabdf5161f5c7c66d4efe1f5ccac83cdf826181d51b46f874f2a3d107ffe6b33f85cb376544e274e0e2da23520b6e1c326dd0a6cc874f86bffb05a42097b5d13c9dd5a861396d43967c70d5f2b487f66a37f634d1038c6b0d05943ff197761e7a53163784e026f657f3c04f0b8bfb9e43e8c0ab2e8dec0ccdab6a6b5d1e12bb4939ca2d4a72b3d7fb48880e1f84e4fd6d1635d6814fc5acdd709947487a242825832444ee3ab2a4d65feaeeccdcf6f46534d6622a7effefae086eb0be801cc072c22a9ae6121954d42b98ae18de799a05514c6a566bd38c46c5f7a48a09631614502d6b055e9db102e2b67f0afb7b31de83a3470f3af0e18a10d76a15a821b360d4339333851ea00d87262347d3f3e48deb3c8511db85ac0905b03a4d4c12549434d7b19b78db48a7921dcbf5123f8de2a6e74b87c7651371a81ca2bfd379fd4298afa3dcffbf0ca640f831237772353849225322e10adc329888d0ddff12a5171a6bbe30bde1570966b9b3edf480978e6037f7885602e5d3bd557b2e9379ee9b52bccf07e2c6ecbe3ec653cb3ced860942788422599b748e3a2617b4db7d53094d0e26f0d8e91ee0c803183fdd5b4db013c83f56bcd7da56e9423bdd670e9cc8f6e4f341f0cae7d44463370af3bb2d9cd8a
#TRUST-RSA-SHA256 3df5cb6bfa051c9873543c43c9891957e24b760f4ab3c4f86115acd4ce6fa9ab39a0c7fbbf68a08412d2fe6945479ac5f5c6a6411d04819118ced3cb358262db4b242267b5d8a709bfbc62885fce66bfe355571f06e07f9ff31188adb1c114044f2ca385fe9d7a63b9da909b5f97b14ab86b187c4b13a2fc208358f7032d69059bf7c9685ebf148210a6dffbcd584bfadb9a43d31670c19c769bf41750633f041ca565703875a219f8a9fde578bbdfc5037af13a03454d36a6f392085a37dda7b1be40682e96f505b8446c550e25b16d41a865c14d3df2a06763ff5711ac7bfbab4c366f5fe746f06c8f0f54e1d30367da88d4ab7727fb829d703f75f97ada12701d92d730d3ab5d1fb734af8e87269d07e48e80ce50c91bcb5abb2c5896d73369b9af86c6c6be9122bcc2b2ad074f221953651e8556a7db40ec2bb715457308f1ecc3488c9a9340db3bea15fe2ce40b1daf1b2214dd678688da29258bb16442d1cf1d2e7bbf51db13d920709246478fd31c0f797688a10ad97c40f5c8bba5eafe3bb9331b53f0ac225feffe1faab6ae9f9f6ccdac63abe184ffca0edc5ffe8b5d82e309249944bd51253857302ae18407f0d96e256b8d956a3389a3d7304e4581168984adada372912db2b69796aa5be91bbd91605a4fa597e722ca4b2efbb7756ed052df7e62b44b53666e754939e437ee9029beb619112604cd9ea6d295e9
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124060);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-1652", "CVE-2019-1653");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm78058");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg85922");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-rv-inject");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-rv-info");
  script_xref(name:"IAVA", value:"2019-A-0356");
  script_xref(name:"IAVA", value:"0001-A-0008-S");
  script_xref(name:"IAVA", value:"0001-A-0009-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2019-0212");
  script_xref(name:"CEA-ID", value:"CEA-2019-0008");

  script_name(english:"Cisco Small Business RV320 and RV325 Routers Multiple Vulnerabilities (cisco-sa-20190123-rv-inject, cisco-sa-20190123-rv-info)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, this Cisco Small Business RV
Series router is affected by multiple vulnerabilities:

  - A vulnerability in the web-based management interface of
    Cisco Small Business RV320 and RV325 Dual Gigabit WAN
    VPN Routers could allow an authenticated, remote
    attacker with administrative privileges on an affected
    device to execute arbitrary commands.The vulnerability
    is due to improper validation of user-supplied input. An
    attacker could exploit this vulnerability by sending
    malicious HTTP POST requests to the web-based management
    interface of an affected device. A successful exploit
    could allow the attacker to execute arbitrary commands
    on the underlying Linux shell as root. (CVE-2019-1652)

  - A vulnerability in the web-based management interface of
    Cisco Small Business RV320 and RV325 Dual Gigabit WAN
    VPN Routers could allow an unauthenticated, remote
    attacker to retrieve sensitive information.The
    vulnerability is due to improper access controls for
    URLs. An attacker could exploit this vulnerability by
    connecting to an affected device via HTTP or HTTPS and
    requesting specific URLs. A successful exploit could
    allow the attacker to download the router configuration
    or detailed diagnostic information. (CVE-2019-1653)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f54bf7af");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-info
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2764da3f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm78058");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg85922");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm78058 & CSCvg85922");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1652");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1653");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco RV320 and RV325 Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

vuln_list = [
  {'min_ver' : '1.4.2.15', 'fix_ver' : '1.4.2.22'}
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'fix'           , '1.4.2.22',
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvm78058 & CSCvg85922',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_list,
  models:make_list('RV320', 'RV325')
);
