#TRUSTED 1b5d3865439afeb2812b2f9f91132ac10d64edde563ec16402b6551afb0c595b91bc59355757cfd8aca43598dc260bbfc614c2541168c414fa693bc024857ed4d7478ca8621a80791aa7fef05d21cb470e564c7d175057a7f2a80ac3e488e84fa4e73892e2cb13ea57827aaf8fdcdd5776e70062eb0d5fecafdb9378728ed189849051cdb92777c87f39c2f585e1f1b13f0fe567f6e1717ae03b70a99fcc435de2f4aab5c5fc3134b13959ad1f9949f66c2a3a131496f1e207e701f771039b1bdf7683da8bd140f664538311d30942aade41ece88699d6435ac491a9a7ba8cda67e1548ae381f89aba0e1aa3839fe9f905a5f2fd0680b40f6b0545f3514226609b4393ee6b17bdca695e914c86ae49ff88ebbbf0d4c7a997c2560b350e5ed273a36df243592baebd8bfc984ade25c1740c7351f16123e7b2f01a328c2068902fdfce18a7ed298b40574f11a59f7877958b44243e1ebfe66cb6e4ca4f4067372f74b18d76bd37cf5c9a0b331f6a9cb39713f220b33092182b25c5c1bd8c9bfc567e5cab9d5ab9bb8359584c0b72c9957a93062849341407f900b9a8b436e1cb3942bfbbfeebd1938e2812c2714c3923ff92c0c925599339c2613e0708582dd95160eaa2e62016b6c1c1b1467722f25f4e7c8f562eac1b476223842dddef80f6a1082b143566f36d05b0f10bab3d1576e07d0fb326c8bc60e66773f2ba7a239e23
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138353);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2018-0293");
  script_bugtraq_id(104520);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd77904");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxosrbac");

  script_name(english:"Cisco NX-OS Software Role-Based Access Control Elevated Privileges (cisco-sa-20180620-nxosrbac)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability. 

A vulnerability in role-based access control (RBAC) for Cisco NX-OS Software could allow an 
authenticated, remote attacker to execute CLI commands that should be restricted for a 
nonadministrative user. The attacker would have to possess valid user credentials for the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxosrbac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c61ac8ae");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd77904");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvd77904");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0293");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
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

var cbi = '';
var version_list=make_list('');

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9][0-9]")
  {
    cbi = 'CSCvd77904';
    version_list = [
      {'min_ver' : '5.2', 'fix_ver' : '8.1(1a)'}
    ];
  }
else if ('Nexus' >< product_info.device) 
  {
  if (product_info.model =~ "^(20|55|56|60)[0-9][0-9]")
    {
      cbi = 'CSCvd77904';
      version_list = [
        {'min_ver' : '6.0', 'fix_ver' :'7.3(3)N1(1)'}
      ];
    }
  else if (product_info.model =~ "^90[0-9][0-9]")
    {
      cbi = 'CSCvd77904';
      version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(7)'},
      {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
      ];
    }
  else if (product_info.model =~ "^35[0-9][0-9]")
    {
      cbi = 'CSCvd77904';
      version_list = [
        {'min_ver' : '7.0', 'fix_ver' : '7.0(3)I7(2)'}
      ];
    }
  else if (product_info.model =~ "^7[70][0-9][0-9]")
    {
      cbi = 'CSCvd77904';
      version_list = [
      {'min_ver' : '6.2', 'fix_ver' : '7.3(2)D1(1)'},
      {'min_ver' : '8.0', 'fix_ver' : '8.1(1)'}
      ];
    }
  else if (product_info.model =~ "^95[0-9][0-9]")
    {
      cbi = 'CSCvd77904';
      version_list = [
        {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F1(1)'}
      ];
    }
  else if (product_info.model =~ "^30[0-9][0-9]")
    {
      cbi = 'CSCvd77904';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(7)'},
        {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I7(1)'}
      ];
    }
  else audit(AUDIT_HOST_NOT, 'affected');
  }
else audit(AUDIT_HOST_NOT, 'affected');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['network_operator_account'];

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
