#TRUSTED 82388ae6198b577cbebee0b2eeba05ac8479e13f5eb208247860a34dcb604570d444a1dbc81b32221cd940e126e04d37218ae0dda6ff2b70f3bbcaeb2fa4fe26c272fcd132627122ab24956b1b1ced67ca7f3548469d7d03cf394978175500b09dd62437bbcbff57d3f5f5c359550c7bc9c6480da7cffdb656e87bddb025444410d48e73d28bced008c59cfc1c80a2e7cb36daed8310a67a87122fd51fda1407a68d7761946691eb211b6f784e6b296a5117d5178dee5e609b41924a935b64611e7402928bda60dd50b30f93b5243d58121c24cfe0060ef5a5828130094604b9a70f813f23ffb5c1e30684dbc4f36da97fed57bfa98e1e07e801161f8952187dff5cfea791cf616cfea1e2176b8f0a4d83ba743ce920d20ca498a85a72862b9bf976d0c8716f41ff0fb4d9bdb4f936b3079c9eba90887111a45d10d8ef0f89f9f4215cef4ba817b4812ff85e768d643e602a6ce488c398f219ebd27ca5d52da44b9519d15411c033efb887c13009f7ed6c7c5c0b2b7f5b63679d8767a9dcc5e6d53b1fb1313b003387d460a37abf4dec5e0a38cf2b391c69f484420d3fda99f241dc2ecc63dea0746696301db4b7d65b0abcf6292fd6cf92852d5502339d6b2a5e51420913244f4ac8e848eb1f8bf67abe678af32ddd88a9f68a9ff06dc9e74e76996c2831dbbba077d048c06d03c84e9fe3f6eaf7dcc19d6c7e1da139775d7b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128114);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1747");
  script_bugtraq_id(107599);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm07801");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-sms-dos");

  script_name(english:"Cisco IOS XE Software Short Message Service Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installed Cisco IOS XE Software is affected by a vulnerability in its
implementation of the Short Message Service (SMS) handling functionality. This allows an unauthenticated, remote
attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to improper
processing of SMS protocol data units (PDUs) that are encoded with a special character set. An attacker can exploit
this vulnerability by sending a malicious SMS message to an affected device. A successful exploit allows the attacker
to cause the wireless WAN (WWAN) cellular interface module on an affected device to crash, resulting in a DoS condition
that would require manual intervention to restore normal operating conditions.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-sms-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22250072");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm07801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm07801");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['sierra_wireless']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvm07801',
'cmds'     , make_list('show inventory | include Sierra Wireless')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);

