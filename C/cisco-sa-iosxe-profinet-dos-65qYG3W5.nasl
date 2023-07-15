#TRUSTED 7f6217828e2a02adb5fa451573cf59556c03691c358742f7750ec15a224b1a35dd58c79072bb34e2d26df759a67db933951f1c88e27316b9acae2233fbdbffba398a8711646c94b7fb21d13e2aeaf6c14558a74062511aa8f43bdf7d6f97dca6af4e7e25980965f505526cf1cec1cb872ad5f11524abf0e84d9f02ea71ddd1ea0fcaf8787a2a79dc775b7df5e7343de233911f9cd7978af1bccf46f2861167fbb655383138f15841a367c2a397085a89dc6b82e01b2af668d99c124db2ee7f95e6521195ad4c7cf2971c00429319d1e18e5190d091df05518f4e869fab0c693207400a5d08d1f95773f8b3a9f1ac36b2d702687797aa506e5cc70295d9abdd9330e838dab48efe7bc0c6b99696798f8616086326d207ece1710d23c7a7dc873baf098adf095beb05ed28a90f88ae86b7d7ddb34e7b9897df05f34aeacb486a3174883f404e2bebd956aefa45377833c9544ba92feffd729433f2b5dfd00f26ece1abfc3a67d6217a1275f4a8b55cfdfcf32cc3350f98db3acf14787e69bf54aa7db0f4273ce14f055789bc3941feb2b45f43a6d79349fcd04c67c8f8cf84c70098a17d5c3986ee1adb85ec53ed038e06b5383a5fcf0c3f0fe5207af38ae5cd48f4d52c47257422ed2bd682405baf926ec9a314315d0613021e8a18105f0bda9395518212b3f260749abad982a3276e1166242c43094d7cbf0b5702b43573bc86
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142958);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3512");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr54115");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-profinet-dos-65qYG3W5");

  script_name(english:"Cisco IOS XE Software PROFINET Link Layer Discovery Protocol DoS (cisco-sa-ios-profinet-dos-65qYG3W5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco IOS XE software running on the remote 
device is affected by a denial of service vulnerability in the PROFINET handler for Link Layer Discovery 
Protocol (LLDP) messages. An unauthenticated, adjacent attacker can exploit thisby sending a malicious LLDP 
message to an affected device to cause the affected device to reload.

Cisco has released software updates that address this vulnerability. There are no workarounds that address 
this vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-profinet-dos-65qYG3W5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aaa4e06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr54115.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3512");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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

version_list = make_list(
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.9.2E',
  '3.9.2bE'
);

workarounds = make_list(CISCO_WORKAROUNDS['profinet']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr54115',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, reporting:reporting, vuln_versions:version_list);
