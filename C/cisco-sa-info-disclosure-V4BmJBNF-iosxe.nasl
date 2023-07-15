#TRUSTED 315b25a2fd880c66b9e8b81983a1a160e3b146d8e2e18d30e4b78f2ee7061bd7b7712445348804fae38838a78b6259b9aab1aa4b3c92ffd7a6c784e2c22c19c22e69ae2a945836daca2e20b9d3463fd721e697c31c37dedfc4b58c57f999669b29fb13ff536abd04cf3c40f88ed2a90136fdc6492ccc26135d01e2050f4165ebe7ea07f670c6571249520f76828d722ec1c613394fa30517975a40f947d1634b40d7762956ed76919f1b2e868be6092083a379a28552d69849c63a05516d4a34fab4ae06cffd52d420396a7b586ddf5e16a7e89e8e5360b6b72a4b71cac1f01a50dc9177b3488ea9c34f3a1b86e7adfc43a0f49e6446b6bc28298ff7194db14ed00c301d75be9834e19dd15f4dea4b7435b64831c64c07e3c5253f55d4a575eb57b51a71802d07b5e24f3687dcb4eebdfa3391bdaad7d7b6a341d29b1ea777ed0913770964991427d38073a206f3952c1f609fc37dbfd652230a84b6b5a16ef5c006b84b25f81017266972baf93c9cde7325b533660a9be309873e32876a0ecef5b17cb585c0e6b04f6c2da757d1a071306e2149ee4990f7e7625fac701f1c6468c2d586155331c84adcd9478b7df673381f59405d7ca3f13577a7ecec47b52e12f6ed6eff10f7123f3d3d5b6b0ef90a4bf04144f64d860c466b10b14520942a4bb92de78844b14fb98b2ad97515f45f02458f84c00c597defeb53a2289e528b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141117);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3477");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu10399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-info-disclosure-V4BmJBNF");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Information Disclosure (cisco-sa-info-disclosure-V4BmJBNF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS XE is affected by a information disclosure vulnerability. An authenticated,
local attacker to access files from the flash: filesystem due to insufficient application of restrictions during the
execution of a specific command.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-info-disclosure-V4BmJBNF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b353e4e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu10399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu10399");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

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
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.12.1y',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '3.10.0E',
  '3.10.0S',
  '3.10.0cE',
  '3.10.10S',
  '3.10.1E',
  '3.10.1S',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.2S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.3E',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.11.0E',
  '3.11.0S',
  '3.11.1E',
  '3.11.1S',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.0aS',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.10S',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7S',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.10S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2S',
  '3.18.2SP',
  '3.18.2aSP',
  '3.18.3S',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4S',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.2.0SE',
  '3.2.0SG',
  '3.2.10SG',
  '3.2.11SG',
  '3.2.1SE',
  '3.2.1SG',
  '3.2.2SE',
  '3.2.2SG',
  '3.2.3SE',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.3.0SE',
  '3.3.0SG',
  '3.3.0SQ',
  '3.3.0XO',
  '3.3.1SE',
  '3.3.1SG',
  '3.3.1SQ',
  '3.3.1XO',
  '3.3.2SE',
  '3.3.2SG',
  '3.3.2XO',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.4.0SG',
  '3.4.0SQ',
  '3.4.1SG',
  '3.4.1SQ',
  '3.4.2SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.4.8SG',
  '3.5.0E',
  '3.5.0SQ',
  '3.5.1E',
  '3.5.1SQ',
  '3.5.2E',
  '3.5.2SQ',
  '3.5.3E',
  '3.5.3SQ',
  '3.5.4SQ',
  '3.5.5SQ',
  '3.5.6SQ',
  '3.5.7SQ',
  '3.5.8SQ',
  '3.6.0E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.10E',
  '3.6.1E',
  '3.6.2E',
  '3.6.2aE',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.6E',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.8E',
  '3.6.9E',
  '3.6.9aE',
  '3.7.0E',
  '3.7.0S',
  '3.7.0bS',
  '3.7.1E',
  '3.7.1S',
  '3.7.1aS',
  '3.7.2E',
  '3.7.2S',
  '3.7.2tS',
  '3.7.3E',
  '3.7.3S',
  '3.7.4E',
  '3.7.4S',
  '3.7.4aS',
  '3.7.5E',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.8.0E',
  '3.8.0S',
  '3.8.10E',
  '3.8.1E',
  '3.8.1S',
  '3.8.2E',
  '3.8.2S',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '3.9.0E',
  '3.9.0S',
  '3.9.0aS',
  '3.9.1E',
  '3.9.1S',
  '3.9.1aS',
  '3.9.2E',
  '3.9.2S',
  '3.9.2bE'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu10399',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);