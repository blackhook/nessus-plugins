#TRUSTED 8f4d7f063dc43436e899cc615948fe7b1305c4053ff7f607de6751f688492f903b53952e795d44bfe56e0f5820778b35a76840f8defbd0feaccdc0f276b4318652aa10292227db3c4b62b1a97f167d8be9e1b546717c76592f4f35e9230834ab569105f6f81fff0acd748a558f1099a4cbb848bad5c52458f5ed63f43e45cd1d14024fd19602a6b53856dddc67297829fb4b4aab304a14309e09912dbfe4684b7a35e9c5c2fce320b5a351892efff1e46273b2a4eafe8b73528b1d4a709b418b623db013cfe88228b21fbd9831f558684c1f1db75e910589201d68514992df5a63f0577160972150db890bfece8e0c6c3738d6e55d684e06812ac3f96d5a427cab5789019b4e48643701bd24a58614add00db194b9520bfbec25e954d2aaa0888cbf3a75f53cfc86c0704ad877d99ba91e208e470cde363e58d7ed30ee05e11a1ecf8488be755d37143fdc19f5413c66788ddba9e9aebf9e2e7b39ae046aad46b5c9a55244cd9f3c4fda9d5805b951b9e745b326aa14a02721faf13c8e563b8588c37d06bdb09c972d982f2f54342d962c196c556614448e9d52059b05a6d59f8d52ef5abda2a6186446c8c7fc32ea34a0b2b15f6877d9e3934501f08d2f325eff5ea28563da5d183bfd9a071ef7fc7dcd107baae75b698e41b6d8a0093531ae027575af4fcd3418a046c0a76c1ee49c98f186c91715635ca59633a95ffc2b1d
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160719);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2022-20748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy33560");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-amp-local-dos-CUfwRJXT");

  script_name(english:"Cisco Firepower Threat Defense Software Local Malware Analysis DoS (cisco-sa-ftd-amp-local-dos-CUfwRJXT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the local malware analysis process of Cisco Firepower Threat Defense (FTD) Software could allow an 
unauthenticated, remote attacker to cause a denial of service (DoS) condition on the affected device. This 
vulnerability is due to insufficient error handling in the local malware analysis process of an affected device. An 
attacker could exploit this vulnerability by sending a crafted file through the device. A successful exploit could 
allow the attacker to cause the local malware analysis process to crash, which could result in a DoS condition. Notes: 
Manual intervention may be required to recover from this situation. Malware cloud lookup and dynamic analysis will not 
be impacted.

Please see the included Cisco BID and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-snort-dos-hd2hFgM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c868e825");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy33560");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20748");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(664);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');

# adding paranoid check, Unable to check if local malware analysis is enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [ {'min_ver' : '7.0',  'fix_ver' : '7.0.1'} ];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy33560',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
