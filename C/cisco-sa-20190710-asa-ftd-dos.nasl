#TRUSTED 2b65c6af25efe2c3af5975fa5b091e203c3215758025225a0b0b02f9dabf5e9dfdf5d5703471b2b6ee9b4375b459bcd9b93cddf9bdb674ae3bda222b135b85faad83eb62bcec7953b1e78a269888ed68c45f190231ccfaca82a52f8a263d31cd6ec4bfc61e92f204e2849b1b581ceba4e677d0bba294eec659f360274e007746acb197c9f27ddcf3df7db65662268db02b0c2b8e188fcb8f30098f863c2b3903d716093e77120804614cb744f967c6aa461be0c8123c197f42736b879356e9aa236c3c8d7f909762ee94b0b6c8018febca3e3b457d6b4543a1a63605cef8f2739db40647f6bdc1c748503dd5322030c47ff0d334793b692a676bba308c4abe66bdb5ae921b77c9d6a35468a6f2d49d7247733c2e4dc3cd9d4e3f5035473e02e22ea93f9c1f375fd5d9c6c7d1906b0dd9758c8a44b681c426ba0d50cba3e4ce4a468b25d67c9b95a6a2eb3adf4c1f651128cb248d598aa8b085c7c751e74b43acd13ea49cddc9762d030bfbf6042a453996752de0bbf170990e9d3018e2d67ef4b2bf1d9c45d026201ad6229d2da21dcb724ff8636550123edb9d1b8869fb38ccd6d35a3d610342b749a39073ed8bf6d90efc4a0ab7566f17129757b6a3245712a3641cd3cdd0437bfbf5cd64b8969724770c0f4f767b2d2241eede68a1e6103a66bdde345443233811c4ff4e3339ae75070fc6680bb33b3012dcd4bcc92a7924
#TRUST-RSA-SHA256 6fb6d61b8a3772283c4247d7879a84bef6d1bf6cfb5c98c838cc4dcd7a9d8233e0595af02fb8094746f6c664c3a4355e138d09c2251526a0222402707eb440a07d76e7c6abd6f271d85e13b83bc17327174950510b64331545e20a4ce407a846322bfaa94aaec53c986e925cd15ad85fead29d748b588d86dcb627dc85cfcbe54297ddd01cf24bcd74fbc2f1ef93f6e6e8901a53403810cbd642efd97fed83dc673e908187315cda4b5c95396a951dbefad61d29c98b1516404f4949e58cf229a279970eb289a3770cf24f12a161cb01f561745c4a99b20967820016f24aa01578a36e991d4c23d9abad43c6f3b527d4b86f476eb904f53bb1439736b9c77ddbf93b99ef8c3319a51927560966ea1bc8200a02f9a6873988e29788d15a7ea88ed51f854d43ee4c1babc2ba87381b46805fe3736bf3406bfeeee98e68db31ba01e279d9988129d260a322627bbf2fef385ed22e95e20350626e95cc9413423f5ee03c6863ef69b68c90a0b509784fbc497a9bdc5eaec428e8801d5b13f15cbb7bd17f07cf6270c2eed0fc6cc6aa3754d132d6c576e66daebbba38c307498dd38236ea891bde60f9ff54189a48415fbe6e12bc63cffb438060e8988d30dfe20a0eb7bb2d6fa9aa36862b92d0541f2d9bbe4e844c9ad013b96f5decfeaa85e828cd68c6023db9bd88fb32bf61c600a4f950fa2aed4e6daff116be7ef615d58db0b8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127118);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2019-1873");
  script_bugtraq_id(109123);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp36425");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190710-asa-ftd-dos");
  script_xref(name:"IAVA", value:"2019-A-0271-S");

  script_name(english:"Cisco FTD Software Cryptographic TLS and SSL Driver Denial of Service Vulnerability (cisco-sa-20190710-asa-ftd-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Adaptive Security Appliance Software with FirePOWER Services is affected by a
vulnerability in the cryptographic driver due to incomplete input validation of a Secure Sockets Layer (SSL) or
Transport Layer Security (TLS) ingress packet header. An unauthenticated, remote attacker can exploit this, by sending
a crafted TLS/SSL packet to an interface on the targeted device to cause the device to reboot unexpectedly.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190710-asa-ftd-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5001de6f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp36425");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

model = product_info['model'];
if (model !~ '55(06|06W|06H|08|16)-X')
  audit(AUDIT_HOST_NOT, 'an affected Cisco ASA FTD product');

vuln_ranges = [
  {'min_ver' : '6.0',  'fix_ver' : '6.2.3.13'},
  {'min_ver' : '6.3',  'fix_ver' : '6.3.0.4'},
  {'min_ver' : '6.4',  'fix_ver' : '6.4.0.2'}
];

is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  else
  {
    workarounds = make_list();
    workaround_params = make_list();
    extra = 'Note that Nessus was unable to check for workarounds';
  }
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['asa_ssl_tls'];
  cmds = make_list('show asp table socket');
}

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp36425',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

