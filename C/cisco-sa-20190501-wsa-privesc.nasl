#TRUSTED 846793158bc2a49cb72058fb113fbea52ab132603c0762ff35e32335094f4d0d330c1b65ce60a90ae2d88b19c63f9c808bffe7bd84279a7d71ea3a31a0b5a9c0844901cd8aab8183188315b2aaa0c0bcc43c64095655e8c567a0559e69043e3aa7c65535ab34e66798fda7bfe3943bc2532278e70850dbff13dd7f59fb56b9a22351a27aceb1a5a719e1284d74ccaad6c8aabc5a5e16a2784df9289de8c6cbee1504885cada9eb052ad4b01d83cea1ef516cd240202919312ea101ce68ec30f48963bdaf4dbec1ee485654a22e0c38d57282fb5f85f215650d4312198ca94462538ef4a13e266e2327c0de39964665b922ffd03e723d2feed5ab6e435af56c397ced43a36af8d1f0ddb58154297d36d0c1329a511dda9fa05dbd472a2a53652378566f481259fa3567cb210c28a4fcf72d3748930f09aadf7bcde9d1aae95ba1488f4aa75cdbf6679dbed4b896ee103cf59738526cb0b3f7a61e3605baf190bf0d79798f6d3f71f04ed725dcc358494b99ace0ade6613ac71b914c8697f532afd4bd221a7299cea4fef70ecc648cb64635c77e271c5722c2d9a73cee3f32840c64b91ccb8b274c1b348c7a3766f819618fccd9f87f5744bb733219c1e7f451ba3953fe4ab1691909e4383ad1d90dce29876691466e3db67df2aa3c1127f7af5513cd1ed8c7056bd9ff15bf7e679b8cbc3f6171434b4f2f21714addba8f1120bd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
 
if (description)
{
  script_id(126916);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2019-1816");
  script_bugtraq_id(108131);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk68106");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-wsa-privesc");

  script_name(english:"Cisco Web Security Appliance Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco Web Security Appliance (WSA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance
(WSA) is affected by following vulnerability

  - A vulnerability in the log subscription subsystem of the
    Cisco Web Security Appliance (WSA) could allow an
    authenticated, local attacker to perform command
    injection and elevate privileges to root.The
    vulnerability is due to insufficient validation of user-
    supplied input on the web and command-line interface. An
    attacker could exploit this vulnerability by
    authenticating to the affected device and injecting
    scripting commands in the scope of the log subscription
    subsystem. A successful exploit could allow the attacker
    to execute arbitrary commands on the underlying
    operating system and elevate privileges to root.
    (CVE-2019-1816)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-wsa-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de4d6664");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk68106");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk68106");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

vuln_ranges = [
  { 'min_ver' : '10.1', 'fix_ver' : '10.1.4.017' },
  { 'min_ver' : '10.5', 'fix_ver' : '10.5.4.018' },
  { 'min_ver' : '11.5', 'fix_ver' : '11.5.2.020' },
  { 'min_ver' : '11.7', 'fix_ver' : '11.7.0.406' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk68106'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
