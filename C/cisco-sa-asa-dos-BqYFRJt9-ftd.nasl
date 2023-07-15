#TRUSTED 26c46e57fc22d8a2544a9fc65e46ecbd15672ac0f8f993de94e6e0d689def1b7f8e12422496be1ddf2d8ff842c755566d22a650b89ea785f618e2464f13ff337875c1b9eb47e925567cda50c6a1942f8afcd227d7307f4d707b2106b9b94cdd114e95d668d388159692d6c27f03ad13df7b962056b4dd546bec980832b1a7a33a0121fd7a9b46c8cd5bdd9c471028e0e9724578d2a4b42609160b6c1bf33099224bfc3acd35dfae89a3f17026eb5ed7aece9647e5722779c076e319240112ac346bee043ae7a54ffa81942d3805832ff5fb5d1ba582364e47fd02dd07c2d417da7f1fb0c6375acf13ed78b409f54d7dd1fa57c1a48b1e9c4286dca75767a2a1b2a0abccfaf17d1bfde62c88f13c98c462f522f20465ebc3902ed5696c2c7d043b45f092386279dfa8c166837a037fb277e04963a495c61569b40d732fd9f491790082214b11281886dedb2c822889b7f6a165d2abda1c0830d5ab70c177de61160b1393715ecf8b01ea44661662870289dac58fc51dc5cf5f9ae2e36d11289dbab877bdeec69650d5b735f078b2f5be16a25fea436439208009ef9017830acc61f01169865f81a74cb5417ee945059b8c4aebdd61dadda1fea933ba23bf29f4402f11494b7b9801347b8770ceee8b41f60adc673d6933fa8c1c0f8486f05479333d09e69a032d82c3f630bba0151e3fec76a38170c3d129f45bbc53c99f0b4be
#TRUST-RSA-SHA256 0e79bf2a9fa9a574dc2a785cf9ac384672ea33d1bf1287b75f7ab5a1473873491ba8388f85395837cef9145880fe8b198bbd792e785e80a29f3b49a15d95a21bb7209ca5f6cc3a9652ee6aa97524334c060e019a59795f7b22de2d70b3322e52fbad2f79541bb5be285228d45ae5eb68b2f837f4aca01ed8b58ec291ffe485094b3fdc7e9073d257d4c00f0115a9ba7a819bd60996a5ee491b43a0aeba1c1b080fb35be2d7b7a56cd8fff727869ffd4776cc432a2fc35a8c2203fe26649b3c064f217d3165b363461e50d84281fa15d5b2aee0a3d379b9801e4b3d9ad0e0c463336544be200d5e2d1675892c95674d784b24febfecb60a59887774611541d75d846f68a6286d79d2ea6d03bb2738ff8755c2c32809bb6fb4bcf4f4abd49abbdb3cef2c646ecf50872ec3f445d07db0eee569732af4fc0f3f1ce555def3ecce832fcc3cd7307e2c8c650485fe7fa796843e8f4dfdb848bd5a28f5f7b766fad6d2970ae5de0dea2f8efdd568b0bd7077094274a0882e9560cc5002f4dd7a05b78619ee880451cd29b2796e9d645952f75f0bbc9018969e67301b397e4f505ea7861438300c6b20b39339340dadfbfdd26c953ff75dc5c6b0898cbbdb18b4ac073e2937ce9f56967d83ea9a21fbe89af6127168693048667a6d0528d3eecd5dd2313125b657935e9fe6bb191d5b5868707ad9ca961116e3c75cfe6fe882cb6aa13e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136589);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3303");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq66080");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-dos-BqYFRJt9");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software IKEv1 DoS (cisco-sa-asa-dos-BqYFRJt9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the Internet Key Exchange version 1 (IKEv1) feature of Cisco Firepower Threat Defense (FTD)
Software due to improper management of system memory. An unauthenticated, remote attacker can exploit this, by sending
malicious IKEv1 traffic to an affected device, in order to cause a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-dos-BqYFRJt9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24d5d1c3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq66080");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '6.3.0.5'},
  {'min_ver' : '6.4.0',  'fix_ver': '6.4.0.6'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq66080',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
