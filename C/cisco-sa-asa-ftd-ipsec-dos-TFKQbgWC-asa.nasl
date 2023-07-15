#TRUSTED 9cf77d716818543a76bb829d4950487209b1bdfe853e5593d510ba95d0beda908b0910529cfe8d51fd911acaab5fbd2a8ce62f8caef01d835ceb16bb35611c434303c6caaf8495871ddf1159f67a34cef2709ceee7ad6c39b9311b412978607267ebcbbd290fe61c044327bdeedc300fd4bedb4fd52fd76fd9557f5a0eecb7dba74decc10599b46ea2d88e491c0e1904e049b63c79e26bed706cf106966fdc48a5bcc41f742db97ef30c45d2ab46434d9097b1cfd38b1be5b74171de30a02fbff5e48cfeb21e96954e77ade2f99ec308ebbfb7c1d8b810c79166afda3f67048998974d3a5647c3fe448103114e5bfc771872a6c0cbcb62418a619a9039dcee136d292821662d4ceaa78312a6c8728bc8292d95c5b593231a9c55095a067be8b77c74b2e02d14250d2193021ced019dfdf54b40d74c53b12251c8160ec9640838c19b12bff11c457e98edc1bc972365d82ff41fd861336d50559873b743ecba12935cb5824219d039a57cdc4ff0296c76c925920e4930ee2500fb7c6d5a5be8ca4e207b416fe6650a974ea21a066f10fc0c3067834777e80e7bc8e0ce2cb1cfbc966c930569d22c64f77fbc47a28f6ab1d37134f79d5946e2e03506a6b4b3b63f0f8a7f8f57625147928df7bf9d7dc05ca0694a9b2a5ae4ccc0e608caf95abc52ab8aed162d8f5a3b11b1dd7157f18c9cb0ef34ec1a03ddefa221c1f36222c1ed
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152024);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1422");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-ipsec-dos-TFKQbgWC");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy66711");
  script_xref(name:"IAVA", value:"2021-A-0337-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Release 7.0.0 IPsec DoS (cisco-sa-asa-ftd-ipsec-dos-TFKQbgWC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the software cryptography module of Cisco Adaptive Security Appliance (ASA) Software and Cisco
Firepower Threat Defense (FTD) Software could allow an authenticated, remote attacker or an unauthenticated attacker in
a man-in-the-middle position to cause an unexpected reload of the device that results in a denial of service (DoS)
condition. The vulnerability is due to a logic error in how the software cryptography module handles specific types of
decryption errors. An attacker could exploit this vulnerability by sending malicious packets over an established IPsec
connection. A successful exploit could cause the device to crash, forcing it to reload. Important: Successful
exploitation of this vulnerability would not cause a compromise of any encrypted data. Note: This vulnerability affects
only Cisco ASA Software Release 9.16.1 and Cisco FTD Software Release 7.0.0.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-ipsec-dos-TFKQbgWC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b3df468");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy66711");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy66711.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1422");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');
if (toupper(product_info.model !~ "ASAV"))
  audit(AUDIT_HOST_NOT, 'an affected model');

var workarounds = make_list(CISCO_WORKAROUNDS['crypto_ipsec'], CISCO_WORKAROUNDS['fips_disabled']);

var vuln_ranges = [
  { 'min_ver' : '9.16.1',  'fix_ver': '9.16.1.28' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy66711',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  require_all_workarounds:TRUE,
  vuln_ranges:vuln_ranges
);
