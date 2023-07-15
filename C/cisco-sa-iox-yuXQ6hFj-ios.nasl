#TRUSTED 5f57043b4090330da5de93b09339dbabdf9c3c22d5d000c89663c6a4c6480a812e52c4528fff2b275c84b21ad3b29b18b28c5819aa9624811567321ff778261a0008499e5f0f605215735883acd4bd47f253788512e28316ad12318d4e4d7f26e3c7c55ad8a0f129f375c9a60144efa782be9731d9f429a4888e8ca0cb91cfb522f1ad6df199c18e410029774c4e8fcf2bec7a14e18d1bfbf93246dccf2ce17137175a36ae81fd61b60abe8f0ae9bc95dec18e5ed9e83f0f0598bc9bc8d1a6122241f426fc8ce95d94192c387d6ca73c7add8052f75f5e5c1dc99318e30ecc4ffe01ae558732986f1cc4963eb3a58523ac00120c84d0c4eae3be6a209170a6ecdf758bea2dd6bba875713e35d12583862b685cb9eb5162c43525f08931d80a1eb5c1d5b700eb621de7e2b0ba4ac84df554344629de269e4fd0c670bda457a69cbe8f73ab525ca0be5d6b6ae408eb46938dcaed3dbdd6eefd0656d6eae0a0f31f23fd109fbe5f42e9f53cc2458ccf2180153676928f8cf39287c45fbd5de809feae0f1af94a1b3aa65d786aa1af5d5e9992e3518dbc25da16b4c94e00e28d6a438c64be1ad9ebeeae2d7c86dfade22742b8b09f749b9bba0fd569599f115a875c75608ace37d649293305c6e001a3dc81058376310ff033eaf929e694265a9d85ded7db0d7c3dc54b709bd327af20df975882857f62da36a52f8017ab2e902242
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160084);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2022-20718",
    "CVE-2022-20719",
    "CVE-2022-20720",
    "CVE-2022-20721",
    "CVE-2022-20722",
    "CVE-2022-20723",
    "CVE-2022-20724",
    "CVE-2022-20725",
    "CVE-2022-20726",
    "CVE-2022-20727"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx27640");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy30903");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy30957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy35913");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy35914");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86583");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86598");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86602");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86603");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86604");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86608");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-yuXQ6hFj");
  script_xref(name:"IAVA", value:"2022-A-0157");

  script_name(english:"Cisco IOS Software IOx Application Hosting Environment (cisco-sa-iox-yuXQ6hFj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by multiple vulnerabilities:

 - Multiple parameter injection vulnerabilities in the Cisco IOx application hosting environment. Due to
   incomplete sanitization of parameters that are part of an application package, an authenticated, remote
   attacker can use a specially crafted application package to execute arbitrary code as root on the
   underlying host operating system. (CVE-2022-20718, CVE-2022-20719, CVE-2022-20723)

 - A path traversal vulnerability in the Cisco IOx application hosting environment. Due to a missing real
   path check, an authenticated remote attacker can create a symbolic link within a deployed application to
   read or execute arbitrary code as root on the underlying host operating system. (CVE-2022-20720)

 - A race condition in the Cisco IOx application hosting environment can allow an unauthenticated remote
   attacker to bypass authentication and impersonate another authenticated user session. (CVE-2022-20724)

 - A cross-site scripting vulnerability in the web-based Local Manager interface of the Cisco IOx application
   hosting environment can allow a remote attacker, authenticated with Local Manager credentials, to inject
   malicious code into the system settings tab. (CVE-2022-20725)

 - A denial of service vulnerability in the Cisco IOx application host environment of Cisco 809 and 829
   integrated service routers, Cisco CGR 1000 Compute Modules and Cisco IC3000 Industrial Compute
   Gateways. Due to insufficient error handling of socket operations, an unauthenticated, remote attacker
   can cause the IOx web sever to stop processing requests. (CVE-2022-20726)

 - A privilege escalation vulnerability in the Cisco IOx application hosting environment due to improper
   input validation. An authenticated, local attacker can modify application content while the application
   is loading to gain privileges equivalent to the root user. (CVE-2022-20727)

 - Multiple vulnerabilities in the Cisco IOx application hosting environment. Due to insufficient path
   validation, an authenticated, remote attacker can send a specially requested command to the Cisco IOx API
   to read the contents of any file on the host device filesystem. (CVE-2022-20721, CVE-2022-20722)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-yuXQ6hFj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6323327a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74561");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx27640");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy16608");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy30903");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy30957");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy35913");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy35914");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86583");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86598");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86602");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86603");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86604");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86608");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx27640, CSCvy30903, CSCvy30957,
CSCvy35913, CSCvy35914, CSCvy86583, CSCvy86598, CSCvy86602, CSCvy86603, CSCvy86604, CSCvy86608");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20723");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-20724");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 77, 250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var model = toupper(product_info.model);

# Vulnerable model list
if (model !~ "IS?R(.*[^0-9])?8[0-9]{2}(^[0-9]|$)" &&
    model !~ "CGR(.*[^0-9])?1[0-9]{3}([^0-9]|$)" &&
    model !~ "IC3[0-9]{3}(^[0-9]|$)" &&
    model !~ "IE-4[0-9]{3}(^[0-9]|$)" &&
    model !~ "IR510([^0-9]|$)")
    audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '15.2(5)E1',
  '15.2(5)E2c',
  '15.2(6)E0a',
  '15.2(6)E1',
  '15.2(6)E2a',
  '15.2(7)E',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.6(1)T1',
  '15.6(1)T2',
  '15.6(1)T3',
  '15.6(2)T',
  '15.6(2)T0a',
  '15.6(2)T1',
  '15.6(2)T2',
  '15.6(2)T3',
  '15.6(3)M',
  '15.6(3)M0a',
  '15.6(3)M1',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.6(3)M7',
  '15.6(3)M8',
  '15.6(3)M9',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1',
  '15.7(3)M2',
  '15.7(3)M3',
  '15.7(3)M4',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5',
  '15.7(3)M6',
  '15.7(3)M7',
  '15.7(3)M8',
  '15.7(3)M9',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M0b',
  '15.8(3)M1',
  '15.8(3)M1a',
  '15.8(3)M2',
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.8(3)M4',
  '15.8(3)M5',
  '15.8(3)M6',
  '15.8(3)M7',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.9(3)M1',
  '15.9(3)M2',
  '15.9(3)M2a',
  '15.9(3)M3',
  '15.9(3)M3a',
  '15.9(3)M3b',
  '15.9(3)M4',
  '15.9(3)M4a'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['iox_enabled']
);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'flags'   , {'xss':TRUE},
  'cmds'    , make_list('show running-config'),
  'bug_id'  , 'CSCvx27640, CSCvy30903, CSCvy30957, CSCvy35913, CSCvy35914, CSCvy86583, CSCvy86598, CSCvy86602, CSCvy86603, CSCvy86604, CSCvy86608'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
