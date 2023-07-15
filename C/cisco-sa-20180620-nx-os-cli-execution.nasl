#TRUSTED ad6be44949850b7ac5afb40b0b0f98ae11051a33c9e3db7d0236e082d80cbe5ce213560c0a637a39cf7ad0ef5ee463eed8606a322ebbcc5964f620bab2e978a8a6504462b800eb3a4526b3a3cb0c26c852e8e2c518e4eaf66b7b76a9480b4e18e68bea96da6687e1e3671c41d42571031bc622b4e10422ef97e4efbce26cd7c406ae73e43308adeb8035e91e18135cfc907e07ccdb7b111d91adc56b1e60da5cc00aa187f15e39d6572d9be11a4d636a30df8eed60bdbf1db9172fec81930f46f6d54d5554a9978ba9584c31ae81b340ad2e5b26ab02fa555454a3d61c9c1cfbe6e65c98f92eacff908274371c65e7585b600037e6070db47f26fe339551c4ad863c3eedabff053ce4c59cb9f607c645184e98a955bad788dabd222c8358f51f377dfb9aca0e9eb1a9bfacf3a9e4c3c826841a60661d4f387be5f81d53a5125a6b5663899ae974db7c901dc2a6afe8e49503dda9ba568e6ea599107cda0e0f340aa38aca387a45a40f242401edd38916ba90dd2797313f5f58513f96670ef367574a452ca46f56552e0832903517c7fb2cdbf5ff4c7b2ed8d2599d2ecdb28feac79fa8d637f5edd330e0854cfa8ab20410f32563e6c6111748571bff9101d05e8f4e39f4111bd79ac4a4e3952a4d7d8e63d00c171cae36d3d05acda5c41eebfd86dd902c4be15b3ba24d5acd3e5ef4c0fafa293cce3c10dcb093fb4d5c8200f8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138348);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2018-0306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve51693");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91634");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91659");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91663");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nx-os-cli-execution");
  script_xref(name:"IAVA", value:"2020-A-0397");

  script_name(english:"Cisco NX-OS Software CLI Arbitrary Command Execution (cisco-sa-20180620-nx-os-cli-execution)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a command injection vulnerability
 exists in CLI parser due to insufficient input validation of command arguments. An authenticated, local attacker
 can exploit this, via injecting malicious command arguments, to execute arbitrary commands with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nx-os-cli-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea7fd148");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve51693");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91634");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91659");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91663");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCve51693, CSCve91634, CSCve91659, CSCve91663");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var version_list = make_list('');
var cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9][0-9]")
  {
    cbi = 'CSCve51693';
    version_list = [
    {'min_ver' : '5.2', 'fix_ver' : '6.2(25)'},
    {'min_ver' : '7.3', 'fix_ver' : '8.1(1a)'}
    ];
  }
else if ('Nexus' >< product_info.device) 
  {
    if (product_info.model =~ "^1(0[0-9][0-9][vV]|1[0-9][0-9])")
    {
      cbi = 'CSCve91663';
      version_list = [
        {'min_ver' : '5.2', 'fix_ver' :'5.2(1)SV3(3.15)'}
      ];
    }
  else if (product_info.model =~ "^(20|55|56|60)[0-9][0-9]")
    {
      cbi = 'CSCve91659';
      version_list = [    
        {'min_ver' : '6.0', 'fix_ver' : '7.1(5)N1(1b)'},
        {'min_ver' : '7.2', 'fix_ver' : '7.3(3)N1(1)'}
      ];
    }
  else if (product_info.model =~ "^90[0-9][0-9]")
    {
      cbi = 'CSCve51693';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(8)'},
        {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(2)'}
      ];
    }
  else if (product_info.model =~ "^35[0-9][0-9]")
    {
      cbi = 'CSCve91634';
      version_list = [
        {'min_ver' : '6.0', 'fix_ver' : '6.0(2)A8(7)'}
      ];
    }
  else if (product_info.model =~ "^7[70][0-9][0-9]")
    {
      cbi = 'CSCve51693';
      version_list = [
        {'min_ver' : '6.2', 'fix_ver' : '6.2(20a)'},
        {'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(3)'},
        {'min_ver' : '8.0', 'fix_ver' : '8.1(2)'}
      ];
    }
  else if (product_info.model =~ "^95[0-9][0-9]")
    {
      cbi = 'CSCve51693';
      version_list = [
        {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F3(3)'}
      ];
    }
  else if (product_info.model =~ "^30[0-9][0-9]")
    {
      cbi = 'CSCve51693';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(8)'},
        {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(2)'}
      ];
    }
  else audit(AUDIT_HOST_NOT, 'affected');
  }
else audit(AUDIT_HOST_NOT, 'affected');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['license_usage_yes'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
