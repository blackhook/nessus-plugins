#TRUSTED 67d5f183234cd787f55f28b6e85c53b448ac5027dfeaed49e5aaa27a293eda7bf358763ce814789058a5141cc4966ac466e16e8c0d8f7982a7dda5de09d40b12675aad64175e610f42d19d9a7cef7502bac44bfc3edd49e4bb646036b44dd0e2dc9e2568c0f854dee7422320f8f5276ced89e592a8c04e2fcc9f2e0191ffac9d2bf423e8f680e4a4cb2c44f965a43501f68321e1dad6f9eb04c214e539ebae9f1c1bbe3b02ebce1015ba663c19fb6e6683c256f186dd78f935d737c99612e2a039fe7e85a685cefbd6a3c6d3c645221d86230bd88f3d97d14e9700848823541028fb45c478d2538b3df365dccd82f204cc01fbf32f714c2de48321f60795f1dc199a0014c4d2f4c3bc0d97db6b4362ebde59e76f86bc601c8dc803062aa4cf71a04ded3f4bdd73189263e2707933edc9244e1ad858449d675240a19d323d2653f2f2da608d864c90a393106f7c8aa6009c879e8785ba4cfe2f50f13f9c5d580b0cc84a0029e4bb908dd4a79f1999be4097627f560cc28d1580f759e5a63592308d0a77bbfecbabb870390b91a71d3d4ed4747a9079ec7f0554b503ea51a1b45b5e6d045d7562131f91425549b1795477e2cccd00c17cf670155317a7b090842c0fc259de8c4e765735faca7e18813502e4be0a6f85a018797701e60ae5e8e151dfac7c6ccf7629658a2984cd361f45b864f6fe00386c079b258505dcc6aa4218
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152812);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/27");

  script_cve_id("CVE-2021-34749");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy50873");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sni-data-exfil-mFgzXqLN");
  script_xref(name:"IAVA", value:"2021-A-0393");

  script_name(english:"Cisco Web Security Appliance (WSA) Server Name Identification Data Exfiltration (cisco-sa-sni-data-exfil-mFgzXqLN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by a vulnerability in Server
Name Identification (SNI) request filtering that allows an unauthenticated, remote attacker to bypass filtering
technology on an affected device and exfiltrate data from a compromised host. This vulnerability is due to inadequate
filtering of the SSL handshake. An attacker could exploit this vulnerability by using data from the SSL client hello
packet to communicate with an external server. A successful exploit could allow the attacker to execute a
command-and-control attack on a compromised host and perform additional data exfiltration attacks.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sni-data-exfil-mFgzXqLN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19f26cc8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy50873");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy50873");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

# Version comes from bug ID affected versions and there's a high chance it's unreliable, so use paranoia
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [
  { 'min_ver' : '14.5' ,'fix_ver' : '14.5.1' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy50873',
  'disable_caveat', TRUE,
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
