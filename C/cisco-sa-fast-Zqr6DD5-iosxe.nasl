#TRUSTED 4ae35ade6fdc8d7afadf873906bd046f0c701ee3c671144f19661f7f71ce06478ece71f7f19b022c3dbaa44de07c2860423ce532fb327a247f79f3f0d0cbe262826d69196c5e8f75cb4abeb305485b7ab241434ec545265cd6b7c7491e64a65faa97df779046e9d1eab47fbc0d58498d63b51cdb9b2392911d7998634a28ea7c16c0eef2b4973de7d8bc17dd6b4b4e89015701c848c22e21c00a589db6ae63d8969c633b74b4356e63b91d76c51c0c4232669dfe22988845943c464a5f310a447c03c341fb5031ef1e3e42a4de6b70dd471f4b0db3020e27158574b9063da97fcd3ad210f07dbac3f05b068835bb05e581cb98151fd463fb8ce43053b6517949d381be563c32a2d3a9e797ea6d3870e1669b9477394204dea590446743d026a7bf07a0b10d0dfed3a9e4c98f42fd8ae44746cb41e2cdeeb8b92487f6c414b2d7975524ce4a3772336524492800cdc90f0938a440c8d32ee3c2877475912e560fd2c0aa1d0e5b432a0f566317eee5765a8422438bfde41778eddb66761305059aaf49909e6a5aa995d995a32fa1d722490dedbeca80ed70c50f11d5669cd5621a142c15af925af8562bed5f974c71453d8a5682c0b7add22ea9c51367108a7385aa9a92649a4f542e8084770d3005ae0dd944ff83eeda9a52ad150586c024b64067fccf1ac312dcb2bd67ae9c80fb9f5014101481220b37b793228ad5208bc59a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148099);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2021-1375", "CVE-2021-1376");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr71885");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu85472");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fast-Zqr6DD5");

  script_name(english:"Cisco IOS XE Software Fast Reload (cisco-sa-fast-Zqr6DD5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by multiple vulnerabilities. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fast-Zqr6DD5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c09b7705");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr71885");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu85472");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr71885, CSCvu85472");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1375");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

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
if ((model !~ 'cat' || (model !~ '3850')) &&
    (model !~ 'cat' || (model !~ '9300')) &&
    (model !~ 'cat' || (model !~ '9300L')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.5.1',
  '16.5.1',
  '16.5.1a',
  '16.5.1a',
  '16.6.1',
  '16.6.1',
  '16.6.2',
  '16.6.2',
  '16.6.3',
  '16.6.3',
  '16.6.4',
  '16.6.4',
  '16.6.4a',
  '16.6.4a',
  '16.6.4s',
  '16.6.4s',
  '16.6.5',
  '16.6.5',
  '16.6.6',
  '16.6.6',
  '16.6.7',
  '16.6.7',
  '16.6.8',
  '16.6.8',
  '16.8.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1a',
  '16.8.1s',
  '16.8.1s',
  '16.9.1',
  '16.9.1',
  '16.9.1s',
  '16.9.1s',
  '16.9.2',
  '16.9.2',
  '16.9.2s',
  '16.9.2s',
  '16.9.3',
  '16.9.3',
  '16.9.3a',
  '16.9.3a',
  '16.9.3s',
  '16.9.3s',
  '16.9.4',
  '16.9.4',
  '16.9.5',
  '16.9.5',
  '16.9.6',
  '16.9.6',
  '16.10.1',
  '16.10.1',
  '16.10.1e',
  '16.10.1e',
  '16.10.1s',
  '16.10.1s',
  '16.11.1',
  '16.11.1',
  '16.11.1b',
  '16.11.1b',
  '16.11.1c',
  '16.11.1c',
  '16.11.1s',
  '16.11.1s',
  '16.11.2',
  '16.11.2',
  '16.12.1',
  '16.12.1',
  '16.12.1c',
  '16.12.1c',
  '16.12.1s',
  '16.12.1s',
  '16.12.2',
  '16.12.2',
  '16.12.2s',
  '16.12.2s',
  '16.12.2t',
  '16.12.2t',
  '16.12.3',
  '16.12.3',
  '16.12.3a',
  '16.12.3a',
  '16.12.3s',
  '16.12.3s',
  '16.12.4',
  '16.12.4',
  '16.12.4a',
  '16.12.4a',
  '17.1.1',
  '17.1.1',
  '17.1.1s',
  '17.1.1s',
  '17.1.1t',
  '17.1.1t',
  '17.1.2',
  '17.1.2',
  '17.2.1',
  '17.2.1',
  '17.2.1a',
  '17.2.1a'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvr71885, CSCvu85472',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
