#TRUSTED 2fa9a9b6093bf6cd99bad929b19635e8a985f8528843bd77b86ead12184c58344a3366754f2317c2dd42bac383dc7f4c64d6d4ee53504c5c4ec3c2dee3870b6046528cfe7e24217e415bc56068829d357d3fec9877e0bb1d0ad31468fa45299bd0f4518264df376b7123df378e38aa2efdaa67765d7d4741c29891492af62f8828100f248ebd1f3bad44c15fc7888963f67b09ecd3cdc0e67168bd862dc261addf2084f69beaa1bab04df655a482e548ec0fbbfc58b1a57a70ba1bdaea2597954eab4706b21c33c7a071c9dcb8f8af2045a09a62d7f7cb001b693f61fd349f8376f5c73ca3c4af81083ee27ba37798395ebe115c211e8bb366c30c34022d109e7b385b6bdb39d0d6019b3c06d787dca77a1934cc0cfe92dcecaf4edf63231b06ae2e9ded196f40a466846ab018f161b1268d41bf4b4ce55b617efaf20660b36932a44c61b2642a9eec9816c7565bab89f13f8c5da990bf7b9d00cad6b5d9257f1025c033b3135699a4cb1499504de65e3d5c5245c5ed6989eb48cc97e2eb731228423834cbdfb5d58b451a8f5dad40e37e1d36e84114dae2319052eaef860cc77b87a4b2c68ce8e9cf52564957a209240ee59dd2b74b8287ea47233f4cd0134580d8101769540d5c191c95d5397681efd56ef84285bb03d468822046435b753638ce61f865735f58ffa6e50d18b954ce2c0f6a97de1faec873b34dbb98c9e54c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137361);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3214");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq24021");
  script_xref(name:"CISCO-SA", value:"cisco-sa-priv-esc2-A6jVRu7C");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Privilege Escalation (cisco-sa-priv-esc2-A6jVRu7C)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by Privilege Escalation vulnerability. An
authenticated, local attacker to escalate their privileges to a user with root-level privileges due to insufficient
validation of user-supplied content. This vulnerability could allow an attacker to load malicious software onto an
affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-priv-esc2-A6jVRu7C
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fab2941d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq24021");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq24021");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq24021',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
