#TRUSTED 6c1b3d4daf81ac8fb2d85b78913410d96a17bc52c5fdafccefbe96a56c1c3a0680d957ac073d14cb7536b53cfdcfc9b17b5fb4053e95eb67cc660067ab5cb5ff3ea14eab0927f69eeeeb759a54046158b501fec7d86a9920703f2afecabae163f4144bc5a6328074fa29a1f6aa4c87e7f334c1c5f473e8c15cff2678033cf2300b81dfe8bdc296637ddf0e8aab2464dceea774a9610cd97bb0dcbd4085856b00592d0cd3820b990835909513ebdad128ad7fd7421fd68f3ec46a4d060b88de79dc5c8203ac036afa31d126645c08624368b33f210076ec0d0142f011190392caef46f0c2eb0a6d4d010576a7a7ff8ad2034cb3e12aa1c64e063f87801bf1760d62c3442c841b123e866a7ae61e006651df27e14e9be0521df9d62936a351259c463157411fd68e2bbb4f35def2a90b9c4f387e5f6368f8584b1b9bed2868475064bac41740d9d6ff1cf17eb6c2a5a7610b7925fa182aace13613cf6a4c409a0f2238cd63de38879ff03679b4f4dda5e531ff2f1be68fc68eec0543dd2e81f7459b45744640906cc9d1bc44d37f6e349ecd2747b6a7ad32527a151b36fcfd54c158a569364cec9d1151759e56a38d712902a147afadf58186578deefb814a55d7c3c29de689b7fa2c89a6f7bba6b05e0cd34c83cacbf05c22966313979ec328b13c060fb7554e1113aeae15fd673133e3cd4ecbd0c584739d80a76162a9b5cf39
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(145537);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2018-0455");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg28189");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-fp-smb-snort");

  script_name(english:"Cisco Firepower System Software Detection Engine DoS (cisco-sa-20181003-fp-smb-snort)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco (FTD) Software is affected by a Denial of Service (DoS) 
vulnerability within the Server Message Block Version 2 (SMBv2) and Version 3 (SMBv3) protocol implementation 
due to incorrect header validation. An an unauthenticated, remote attacker can cause the device to run low 
on system memory, possibly preventing the device from forwarding traffic.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-fp-smb-snort
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3e0d812");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg28189");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg28189.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(19);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
upper_model = toupper(product_info['model']);
is_ASA = get_kb_item('Host/Cisco/ASA');
NGIPS = toupper(get_kb_item('Host/Cisco/Firepower'));

// Check Only Affected Models
// Advanced Malware Protection (AMP) for Networks, 7000 Series Appliances
// Advanced Malware Protection (AMP) for Networks, 8000 Series Appliances
// guessing on this one from cisco datasheets & can't find in lab
check_amp = upper_model =~ "AMP[78][0-9]{3}($|[^0-9])"; 
// Firepower Threat Defense Virtual
check_ftdv = 'FTDV' >< upper_model;
// FirePOWER Threat Defense for Integrated Services Routers (ISRs)
check_isr = upper_model =~ "^ISR";
// Next-Generation Intrusion Prevention System (NGIPSv)
// Virtual Next-Generation Intrusion Prevention System (NGIPSv)
// Host/Cisco/Firepower=NGIPSv for VMware (69) Version 6.2.3 (Build 83)
check_ngips = "NGIPS" >< NGIPS;
// Adaptive Security Appliance (ASA) 5500-X Series with FirePOWER Services
// Adaptive Security Appliance (ASA) 5500-X Series Next-Generation Firewalls
check_asa = upper_model =~ "ASA55[0-9][0-9]-X" && is_ASA;
// Firepower 2100 Series Security Appliances
// Firepower 4100 Series Security Appliances
check_fp1 = upper_model =~ "[24]1[0-9]{2}" && !is_ASA;
// FirePOWER 7000 Series Appliances
// FirePOWER 8000 Series Appliances
check_fp2 = upper_model =~ "[78][0-9]{3}" && !is_ASA;
// Firepower 9300 Series Security Appliances
check_fpsec = upper_model =~ "93[0-9]{2}" && !is_ASA;
// Industrial Ethernet 3000 Series Switches
check_ie = upper_model =~ "IE-3[0-9]{3}-";

if (!check_amp &&
  !check_ftdv &&
  !check_isr &&
  !check_ngips &&
  !check_asa &&
  !check_fp1 &&
  !check_fp2 &&
  !check_ie
  )
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '6.0.0.0',  'fix_ver' : '6.1.0.7'},
  {'min_ver' : '6.2.0.0',  'fix_ver' : '6.2.0.5'},
  {'min_ver' : '6.2.1.0',  'fix_ver' : '6.2.2.3'}
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvg28189',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
