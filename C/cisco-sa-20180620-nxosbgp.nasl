#TRUSTED 9e30806aee1933ef3dff05489f9a0eff7886e0fb60490ad7809dd372ec69488b56419b6cdde5a1c0dea1302ed7bd521ce3af97956ddc54ae4c1cbae8edbb166f197f87d38bd3b780f70b93d52b446f419e12d2165d0b0fa9d978e5bbe654e97afffc04524d3f0d7f5f77ddc464d2359fa7e63c71777e046cbd7448f6e57258fb6e6e428478a70ee8a9b127e64923be165e6f345d81f7da99bff160db0cb2ba832cebd8b94ceab3cfe9c049383725ac76db262aafde7efe56c78c8b8c24f5bab799bb4b11f1c4e68d96f8d0fd6d4803bda838d568bbce436fcf83694c19bf8cae7346e313e3f0f989d54cd56ab2c386dca5741f562fd98d8fa51e0eff0774eb3612f523c641883eac32333bbbf28edd2ac32e943a5da0e4d975d21bba26f13d8078d065ccb8f7b7a51bbc736d03fc01d90cd991623ca472bbce87cb43a5eb2094000cb3364608c0f3090e622912ce0fbb3ac244f05d2592bea5b832414e3adbf9b9d831e8bda22b41ae12315b99a9fd4ad96b2af23327759ec1ae5c96735d07e91e58c88c49e639f4f319071fa7219b8f78bd82edd6857dc186f96e38dd0f5b66a3aafc324aa6cf7a6ff6b9eed1a7ad4dedd5a87180f5bb5faee2578d9f4bf8e4a230430ca125985b22d342f9cc7ad97e8a45e6b2bc4b69050417f1599c0f955563fe58033ec5cb48f97ae6649aa3b539b0125fdb2ab7cfc65808cdaf4561f5d3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138351);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2018-0295");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve79599");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve87784");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91371");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91387");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxosbgp");

  script_name(english:"Cisco NX-OS Software Border Gateway Protocol DoS (cisco-sa-20180620-nxosbgp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a distributed denial of service (DDoS) 
vulnerability in the Border Gateway Protocol due to incompleteinput validation of the BGP update messages. 
An unauthenticated, remote attacker can exploit this to cause a denial of service (DoS) condition due to the device 
unexpectedly reloading.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxosbgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eacb926e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve79599");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve87784");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91371");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve91387");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCve79599, CSCve87784, CSCve91371, CSCve91387");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0295");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';
version_list=make_list('');

if ('Nexus' >!< product_info.device) 
  audit(AUDIT_HOST_NOT, 'affected');

if (product_info.model =~ "^30[0-9][0-9]")
  {
    cbi = 'CSCve91387';
    version_list = [
    {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(7)'},
    {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I6(2)'}
    ];
  }
else if (product_info.model =~ "^35[0-9][0-9]")
  {
    cbi = 'CSCve91371';
    version_list = [
    {'min_ver' : '6.0', 'fix_ver' : '6.0(2)A8(7)'},
    {'min_ver' : '7.0.3', 'fix_ver' : '7.0(3)I7(2)'}
    ];
  }
else if (product_info.model =~ "^(20|55|56|60)[0-9][0-9]")
  {
    cbi = 'CSCve79599';
    version_list = [
    {'min_ver' : '6.0', 'fix_ver' :'7.1(5)N1(1)'},
    {'min_ver' : '7.2', 'fix_ver' :'7.3(3)N1(1)'}
    ];
  }
else if (product_info.model =~ "^7[70][0-9][0-9]")
  {
    cbi = 'CSCve79599';
    version_list = [
    {'min_ver' : '6.2', 'fix_ver' : '6.2(20)'},
    {'min_ver' : '7.2', 'fix_ver' : '7.3(2)D1(1)'},
    {'min_ver' : '8.0', 'fix_ver' : '8.1(2)'},
    {'min_ver' : '8.2', 'fix_ver' : '8.2(1)'}
    ];
  }
else if (product_info.model =~ "^90[0-9][0-9]")
  {
  if (empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
    {
      cbi = 'CSCve91387';
      version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '7.0(3)I4(7)'},
      {'min_ver' : '7.0(3)I5', 'fix_ver' : '7.0(3)I6(2)'}
      ];
    }
    else
    {
      cbi = 'CSCve87784';
      version_list = [
      {'min_ver' : '0.0', 'fix_ver' : '12.1(3h)'},
      {'min_ver' : '12.2', 'fix_ver' : '12.2(3j)'},
      {'min_ver' : '12.3', 'fix_ver' : '13.0(1k)'}
      ];
    }
  }
else if (product_info.model =~ "^95[0-9][0-9]")
  {
    cbi = 'CSCvc88167';
    version_list = [
    {'min_ver' : '7.0', 'fix_ver' : '7.0(3)F2(2)'}
    ];
  }
else audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat' : "router bgp"};

reporting = make_array(
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
