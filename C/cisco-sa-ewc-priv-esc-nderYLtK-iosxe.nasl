#TRUSTED 39289ebb5334cb7525e9f254105c238c7ab3c2e8bc2063e8a6cac2f1ec6c32242765e7ef2c3c670a994118dfa9ea84e7c5251656a1651776fb5275ed46eec4d1e2970db1fe196d4a8b1f59da22a0ad7b2c0a91d1052fb7b8f68842e285606df5d8a8a432f37a34fbcecce52608ff2d1ef40bc33f373ea35aa3e04270abdb40841b0e7e26d6284ebf3a07a8df595b55edb40ff6efe477242f2f5140fb283ac9b5525c124950841c1283cc9346f4aac5ea64925dfea47e6f414a4d9d4da0cf7c73d50eba45b97a95d2eab153b51252b56f6b67ff65e834acbdb8d4372a2dc6141ee7a815008b96b6443f079c0f228bc5b636283c37dfe55914307398087fa375371038653ac1afd18b6cc0f458b5405bd0028acd6fd6b4b99d8ecd6f45821005875b1b4c033e1c8f0ffc33b7428689cb6b9dfe20afba9c3dc2f0c74e4a40ecd9b494f6b26c1f95515028b772e8c0685e13932e305d5b181f630217324f3f5db4f1133094b2728baa159c20b66b70d7b2d8aa95f006c433473cf1633cdecbaa0b63c077df814f721347c3ce8662fbc0d3fded285816ec2cfece6152218c9bc2e3de1137b502f8714a90802f100fd76eb4eeabf64a78ecf4a7534d52d72fa690680398516f33392e10a8e8d1915e62a86834ca673c2550a29811e3190ed8f51e3b2cb4aae8cdb76110b063609f707b3e9cb7e6e80dbf501ce486ddcf2c458d2dfc81
#TRUST-RSA-SHA256 340f6ac093b11a7ae488661895712fa7c624cd76c4b0f1f1fa1a74c6c67548e7adc9443a8339c43f95ff8a8ad1ed4fe2aa021170bc56f30a869854ba50f10a1130f95a5afc746071624047c094fd877e4c54c78293075c79a5f17137cc33636c506ea65c41e3de162fc93b3badbf064ab43f44cdd71cfa0481a63bdff549566d1bdb08521e4594bd27aae2627218344d7aceedfbdc2d4c55927bda9cb6861f31f1ba29a35bf6e84f6cf7b9412a8524fdab139a8f3960b34d3c0071f872d7b886cfd767f570a3f3ab91ba25cfad7c8d4132897af116a0abccd2c529dd69a458f39c9716e3b894a0a02a35aee60bfea59744a94e9da1a79ab38b06987912d9483faa6bfd6f22909741ff5abf603ad7ed8bb41e7df50177d3bb178be8b2976d4aafc2e5b5721cda51830d1c9d0ff18f9f662b3101b273918664e55316fe06bb7bfffe49a44ec46f1947056da5306fde96821c2ab5cd864cf45d97edf6d0c702899fe2052330e06020d874b6d0ecb27ecaf24242b345dc9fa541339025983f52f6a47130e149dfc346e9ad03603f36090f639b966747ee2b88ecec30b8f4f311c02821d323266f0f7f6e81ce2bd77a49dad7379b8c8682735a58048119d20cadba566edea7dec36ecca8e4bc69db228cbf0bf8b275a0c7a33622a9a9022e6443d5d029f18725a4607cde17a29165cbfd1da6504a594a9df084c68253f0de12fc2449
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165530);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-20855");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa23357");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewc-priv-esc-nderYLtK");
  script_xref(name:"IAVA", value:"2022-A-0390");

  script_name(english:"Cisco IOS XE Software for Embedded Wireless Controllers on Catalyst Access Points Privilege Escalation (cisco-sa-ewc-priv-esc-nderYLtK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the self-healing functionality of Cisco IOS XE Software for Embedded Wireless
    Controllers on Catalyst Access Points could allow an authenticated, local attacker to escape the
    restricted controller shell and execute arbitrary commands on the underlying operating system of the
    access point. This vulnerability is due to improper checks throughout the restart of certain system
    processes. An attacker could exploit this vulnerability by logging on to an affected device and executing
    certain CLI commands. A successful exploit could allow the attacker to execute arbitrary commands on the
    underlying OS as root. To successfully exploit this vulnerability, an attacker would need valid
    credentials for a privilege level 15 user of the wireless controller. (CVE-2022-20855)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewc-priv-esc-nderYLtK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26925ed0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa23357");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa23357");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# As of 2022-11-09, paranoia is a temporary mitigation for FPs
# while waiting for a way to detect Catalyst Access Points
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.11.6E',
  '3.15.1xbS',
  '3.15.2xbS',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1z2',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.2',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa23357',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
