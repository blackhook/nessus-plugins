#TRUSTED 7d6939e834319c853fc0e998912d9a671f44f647ec3c10aa00854b30b1563fea078ff5ed6d4ef4a024c3d97f200c6a1fe531a720bfb294a2c3caf4efcfd1c960d714b78f4cf8bc9c032a1f9eb38ddfd0d12a4e09b0e7e79e24b73c620d415850078fcd34c3b60ed146024a0db55e25e5f934f556c59030b92c8e06d42b60a002e4433c294f637c967cf95a881e9cf6a66ded4948ddbfe67adf30e12c6f7b370187a3d4034133e6fa66d02b410d52ae45d43e4db030598b1360816bf92ddfb99dbdc1f63e56db69bd0706fe9ca2797eb7df5e561859122ae289c97487be37613791f4ea3a884f9b1e6b7af6ab318aeeb5ee182727ec9c71cd7aaa04c850f0a32f7a7dc707b900b7c3e7520a9a3358f16f70c5381e25e9ed1a54aacb99658515be7bd0bf601ff10b60ff9490edd5f0361de8bda200120d4dac95e9197247a06ab21784982655b9bd34254e89284e6bc50d91f7c71da13e0f896c9733c374abc897379eeb5b48918795aeff6ee4b213414919a802a9c63c2e438439193b4ba2f056987d495aeae290fc12093155e6d7e14098c48762aee424b42ef0cd5a3f365b5897ed6f8c076d489a39325e6f79864ea34b1a282df7c35e2f5fb5edcfe19c8e304264026dd6d9922c05c0b8f48ed53898b5d12951036846036bf4a1a32ca76050a073be73330f2aac526be7a1ca56c51800540710fdf7482025a62595fd70595c
##
# (C) Tenable Network Security, Inc.
##
include('compat.inc');

if (description)
{
  script_id(103817);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2017-12246");
  script_bugtraq_id(101165);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd59063");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171004-asa");

  script_name(english:"Cisco Adaptive Security Appliance Software Direct Authentication Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Adaptive Security Appliance (ASA) Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171004-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed9eb8d9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd59063");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd59063.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var version_list = make_list(
  '9.4(3)',
  '9.7(1)',
  '9.8(0.56)'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['aaa_auth_listener'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd59063',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds,
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
