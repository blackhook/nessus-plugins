#TRUSTED 6e089c74d57c94181c2521037a057a16ad75f6ca5a233fe7c6e28da6ebbe3b1c41d4fb8550e1b2bbbdc12cbf7565fc932eb41d0d7ef2916182fbc86547c74b7d6bfd75db335089c1db6e341c46b264f46f39fc531d33178b32800a1b24ab084e6f099f083e1a0717951d31fae51b93dcc1eabf7f762861f720c188bf9dbc723d5de350d2553901e1900db8e69616518d33b9fb73e9ced7ef8c5be55ea1721bfdb3ff43f5dadf364810bb0d87277232d7b91f6902202548511512ea4d976c974676168905e0984322694ec9f500d97ccf1ea0e94d17c44e642d4361502fd60f34030e05ae871ea9c5600df757bc595b50c21e40921a13a9acf6107cc3262d48dbc648ad93811810a6879732afe035425fb1b306ffc487b7132793929be63d55bad7615cee4e016063c3ae718591428071f91c05c81d134e65ba4631703ab261d0c9d5a4abcec016af7977c42b4a105df4a393bc6f22c71321ebc0cdcc9bdcff5d7f3248aebf24b5f6c892dcd7d81bb84ecbb52435803e0a98bdf4436ab5efd051dffdc82bf5b0d0d3cf6f887dbd40465c34fd653aca7d6fbb3b28c3f07b0906f01410275e06565d71393ae25933a033f2b000beec89caa2dd2e7a1e029282f7e56a0d467512c26360c7e4ed847ddbc18de125ced24e3dcf7b6c5a42cc31d3c1d4ac1e5a704e9193deb1f38af58ba046b66a715fa2fed1060c6c1e28f7e0f256d8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148096);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1390");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu78930");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-OFP-6Nezgn7b");

  script_name(english:"Cisco IOS XE Software Local Privilege Escalation (cisco-sa-XE-OFP-6Nezgn7b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-OFP-6Nezgn7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8408b84c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu78930");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu78930");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(123);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '3200')) &&
    (model !~ 'cat' || (model !~ '3300')) &&
    (model !~ 'cat' || (model !~ '3400')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
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
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu78930',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
