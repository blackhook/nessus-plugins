#TRUSTED 956daeafc0e4753106f42912e917405b77ec5bd607178b0bf80f9eba9bae94f7dda650d3092af5879a4ba3a56871d1d097840b7db9bbdbca504345c39894fe96c16b05b555729f82a4c2be15a5e131a3d57e2b2b68a07a63c01af374bad8b81cd396982e99681484a0172ba73f858606cb10dd9ca84c31cb992b46b98551a4dcdc2652ffb2e0fe67ca3f4e13f35d7af569d3626c552e0ea7a6084cc5237ec3c88daf9c41969a49a26391b2f119feaaaeaa7cb2b87fe18cdc3527b841c69d1670f27a739d15e4645213620c878d9a85184f18c406e11eee7534564291c27c882d41b0c544b23fbac26b617b323d265a8a3e5e652ca11832569b6e6f5c4d933ca400d4ff3b95a4322d0ef062e9bb09c1ac7d9a24e3902b8230f0bcfdce4f2f091904b5ec25d7a2f945a2839f1a2dd26d1e28566854a89c5dd8e4e4c90a264469cdf7997d85c51f786b358525d2ee16d7199f2e2ea346a805609dc0fa39902c5d1a2ec790de5e7f544bf954f160f9494ea848d1dfd6374b0db5c3fcd16c277357e74999681cc377f74de7767e2c0e5f522e7e0c71c813cf09afc75f89ad55d9c09d2195948dacc50c06247bb71bfff2611cf04841d5e22f39119e13616c5e3f35c1ecfe41046400e9d973a3b74edb0a570578ab9251faf7cd73c7a65994c8e6b87061e100e17f9745a5abf3af0993d6f1425e1f82e0d41278d3c38c497d8b8e0dff
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138346);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2018-0303");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc22202");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc22205");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc22208");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88078");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88150");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88162");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc88167");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fxnxos-dos");

  script_name(english:"Cisco FXOS and NX-OS Software Cisco Discovery Protocol Arbitrary Code Execution (cisco-sa-20180620-fxnxos-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the
Cisco Discovery Protocol due to insufficiently validated packet headers. An unauthenticated, adjacent
attacker can exploit this, via a crafted Cisco Discovery Protocol packet, to execute arbitrary code.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fxnxos-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f92e2bfa");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc22202");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc22205");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc22208");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88078");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88150");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88162");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc88167");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvc22202, CSCvc22205, CSCvc22208, CSCvc88078,
CSCvc88150, CSCvc88159, CSCvc88162, CSCvc88167");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
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
var version_list = make_list('');

if ('MDS' >< product_info.device && product_info.model =~ "^90[0-9][0-9]")
  {
    cbi = 'CSCvc88150';
    version_list = [
      {'min_ver' : '5.2', 'fix_ver' : '8.1(1)'}
    ];
  }
else if ('UCS' >< product_info.device && product_info.model =~ "^6[123][0-9][0-9]")
  {
    cbi = 'CSCvc22208';
    version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '3.1(3a)'}
    ];
  }
else if ('Nexus' >< product_info.device) 
  {
  if (product_info.model =~ "^(20|55|56|60)[0-9][0-9]")
    {
      cbi = 'CSCvc22205';
      version_list = [
        {'min_ver' : '6.0', 'fix_ver' :'7.3(2)N1(1)'}
      ];
    }
  else if (product_info.model =~ "^90[0-9][0-9]")
    {
      if (empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
      {
        cbi = 'CSCvc88150';
        version_list = [
          {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(6)'},
          {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I5(2)'}
        ];
      }
      else
      {
        cbi = 'CSCvc88162';
        version_list = [
          {'min_ver' : '0.0', 'fix_ver' : '12.2(2e)'}
        ];
      }
    }
  else if (product_info.model =~ "^35[0-9][0-9]")
    {
      cbi = 'CSCvc88078';
      version_list = [
        {'min_ver' : '6.0', 'fix_ver' : '6.0(2)A8(5)'}
      ];
    }
  else if (product_info.model =~ "^7[70][0-9][0-9]")
    {
      cbi = 'CSCvc88150';
      version_list = [
        {'min_ver' : '6.2', 'fix_ver' : '6.2(20)'},
        {'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(1)'},
        {'min_ver' : '8.0', 'fix_ver' : '8.1(1)'}
      ];
    }
  else if (product_info.model =~ "^95[0-9][0-9]")
    {
      cbi = 'CSCvc88167';
      version_list = [
        {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F2(1)'}
      ];
    }
  else if (product_info.model =~ "^30[0-9][0-9]")
    {
      cbi = 'CSCve02459';
      version_list = [
        {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(6)'},
        {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I5(2)'}
      ];
    }
  else audit(AUDIT_HOST_NOT, 'affected');
  }
else audit(AUDIT_HOST_NOT, 'affected');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['global_cdp_info'];

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
