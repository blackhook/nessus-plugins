#TRUSTED 2fb6e97cd08851b4dca6131e576f70a02c7b2a963dcfb32a4dfdcb4d928e4020392bd18a9c1f603d3c2487dfc709896e32f24e6e265191c1b164abb10da7a83bf53d820e857d4afcf431ef1130b372267ebb5444557a90e56758f2d1d06203e1a170161387cc8552c59caf976100274a2a2b69b4a1bfa5a77ab51f7ae4dd38c1574e44de543870d7f7b22c6cc27dddb709e417b6b83aa5cb8b70ca5cd6aa04fb9e34463a51d99a1cfa443f523dbdf9bff9ccec50049de6d391bbe91f31007affc197ea07c0f219b1769ffc845f34f82b03ecd97f0d22cd4df2efbae9fdebc0bbe2109504381be6331320bd988d176e36a49e47d2b918a273aba13c4ae0e255aee4e215391950733735ab9dec9aea8bdab2a847673b551e1a38ebd1d2f5a6f81aa4478114a538501897636ec9b8d199a74fde09692146c1b2c8afc6073989b090adc29d67238d6584af8d79d8e1814ac0329c316da19dd8609536d876f57030848df7df5c0aad005e3dda53c0bd3573e6d49c1d982a833a4b626279c46a5b9921d1d618c486e48a4fe4a329bb02c3199034e097a197a0473aeb41bde5d30eb7d605cb4d949252cb3568e850a7523ad3138f135917b7cb8e52fd4aa21243973d8c5dca0a20a0a35f2d943a3b2265e9cf9f7c940cc7a68adf437aa7293023534be62ac2319a9f822e3db81fdcd7474befe78ebb12b792f5f98ea1a09bcea46fd6ca
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159715);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/03");

  script_cve_id("CVE-2022-20681");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz37647");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-priv-esc-ybvHKO5");
  script_xref(name:"IAVA", value:"2022-A-0159");

  script_name(english:"Cisco IOS XE Software for Catalyst 9000 Family Switches Catalyst 9000 Family Wireless Controllers Privilege Escalation (cisco-sa-ewlc-priv-esc-ybvHKO5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco IOS XE Software for Cisco Catalyst 9000 Family Switches and Cisco
    Catalyst 9000 Family Wireless Controllers could allow an authenticated, local attacker to elevate
    privileges to level 15 on an affected device. This vulnerability is due to insufficient validation of user
    privileges after the user executes certain CLI commands. An attacker could exploit this vulnerability by
    logging in to an affected device as a low-privileged user and then executing certain CLI commands. A
    successful exploit could allow the attacker to execute arbitrary commands with level 15 privileges on the
    affected device. (CVE-2022-20681)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-priv-esc-ybvHKO5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34eae375");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74561");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz37647");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz37647");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20681");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9300|9400|9500|9800|9800-CL")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
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
  '17.6.1w'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz37647',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
