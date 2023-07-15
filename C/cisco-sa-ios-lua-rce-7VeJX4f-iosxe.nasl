#TRUSTED 2090d4e3b093b7ecc3ba3dc939ff6976a249f8c4b8599d69391b1830b06d8705acaf11fb09fea1eff0d593dcea9222030a7913c110bd1c29a9d44426f5cc9b581aabd18d58033694ea379397ede813d44f57c6b6005a3abd16ac968a770379d48189d08dc2b36708dfa4bfea8d29d962d1a9217d0e7613a825c9fb781660f277e4ced1950e39a41375b0add0edb39c17ff66eaa25d5ceab642a418c0fd030681a1eb63ba1f2217fc2321cc2ef72fccf87e3f0d9fd0635c168d8b0818858b670b3e304151fbd1269408bfa49a96454e142363248b3f094ce40f936535b899fd82e325d7308cfe2e65e750a309b01a33be4f3be7eada79bf36a8ab768a1ab3080a777950411938341d647f827ba4b5ded495f02652a1109d06e86e655e7024bca15833ced5fe6ab4fbfd822be789735f152a30ef31f67f93f60fe3d798ec53436e0703bf2ddcd04fb5f749aa9ff67365cebc4c16e5b8749b8c65121f0e8259dcdb75d16fe09b22f93796523a2dd1c5e97f63103052a8d9998aa192c21f3079eedcb1074f86e66dfd57232355ed1de298f06da682bd23e371bd730927275b3b9bc73ada59f61b99c8c499048b326848ccba6ad9bcf97ac14540e5be8527803627c5263ea9560532dfcbc71ca1a934edc676a42c2c4f5c1aa915a394382323ceabde44d1da7cc339bc304f5c3dde768b12df833d5eb1083a2dbc6f336c82ce91b98f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141113);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3423");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs58804");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-lua-rce-7VeJX4f");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution (cisco-sa-ios-lua-rce-7VeJX4f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an arbitrary code execution vulnerability
in its Lua interpreter due to insufficient permission checks on Lua function calls. An authenticated, local attacker 
can exploit this to bypass authentication and execute arbitrary commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-lua-rce-7VeJX4f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d0a7b31");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs58804");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs58804");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];

if (model !~ "ISR" && model !~ "ASR1" && model !~ "CSR1")
  audit(AUDIT_DEVICE_NOT_VULN, model);

version_list = make_list(
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1s',
  '16.9.3',
  '16.9.2s',
  '16.9.4',
  '16.9.3s',
  '16.9.5',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1e',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.2',
  '16.12.3',
  '16.12.2s',
  '16.12.1t',
  '16.12.2t',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.2.1t',
  '17.2.1v'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs58804',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
