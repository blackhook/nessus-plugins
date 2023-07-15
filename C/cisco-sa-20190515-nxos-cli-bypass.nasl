#TRUSTED 46b7291cfe077128afea40c915017d6bda4e1cd6e27e949c14b5ad0993c4f6ac6889f246016de83fbe1020481c710396dceb770fa47087e63f46ed211d58ec2ffc4f4d7e2b1fc4c15ad6caeffb22d97cb019529c037913c5edb0475f32b086aae466efb0cfb09b45fab5517ffe8e7196344d262664b156a7d8d4bc19ac1e1f343a070d65a779fe41ac5779c30ee37eb67a864355d854d7153cf9590bfc7f4edb1c694ccdd20c5339b1e95b2d281a376a371289dca67618b996eefdbdf2577534178fd34eda1c999c25ab2a4a99481b14fe39f2df3dc7d54affc37a80d89f4c68cca1e79a7136e51a837755fcf8ec834034413385961136c91e83c8f780b15cdd44527b698c716313e8badcf246e8c3e279d6440ebd9c027eb2e87e8f92a9db823fde320bbc67d1daab213039b6ab4df2761dedcfd5e4af50162de4987a785aa55bafdfedaeb27d4574d06b201bc5a618d403ed993a26d007a9287e0c6a85a5b87f7782cd8de93420f5c3afce4de0fbc45163e8e3d76bd61d06c977964276093cecdc249d3024ead60a0474d8008cbaa546d3034a77272c8018e37eb213af5b9f76d005559f3788608a23ab0c4477f07815a3410e88bebb4fecfda52f677eab893364eaf629edfb938babcca26b7c3d056913647ded2fd82dd80cf9077e9a97b109aa35a5a4506b87fea4e1188b15879dadab8f965e84f9f9cba127d9ba7e338d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(139666);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/14");

  script_cve_id("CVE-2019-1726");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99247");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99248");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99250");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99251");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99252");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh24771");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn11851");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cli-bypass");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software CLI to Internal Service Bypass (cisco-sa-20190515-nxos-cli-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Computing System
(Managed) is affected by following vulnerability

  - A vulnerability in the CLI of Cisco NX-OS Software could
    allow an authenticated, local attacker to access
    internal services that should be restricted on an
    affected device, such as the NX-API.The vulnerability is
    due to insufficient validation of arguments passed to a
    certain CLI command. An attacker could exploit this
    vulnerability by including malicious input as the
    argument to the affected command. A successful exploit
    could allow the attacker to bypass intended restrictions
    and access internal services of the device. An attacker
    would need valid device credentials to exploit this
    vulnerability. (CVE-2019-1726)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cli-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d14497b3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh24771");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99247");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99248");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99250");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99251");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99252");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh24771");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn11851");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the appropriate Cisco bug ID:
  - CSCvh24771
  - CSCvi99247
  - CSCvi99248
  - CSCvi99250
  - CSCvi99251
  - CSCvi99252
  - CSCvh24771
  - CSCvn11851");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1726");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");

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

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

var vuln_ranges = make_list();
var cbi = '';

if('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
{
  cbi = 'CSCvi99248';
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '6.2(25)' },
    { 'min_ver' : '7.0', 'fix_ver' : '8.3(2)' }
  ];
}
else if('Nexus' >< product_info.device)
{
  if(product_info.model =~ '^([39]0[0-9][0-9])')
  {
    cbi = 'CSCvh24771';
    vuln_ranges = [
      { 'min_ver' : '0', 'fix_ver' : '7.0(3)I7(3)' }
    ];
  }
  else if (product_info.model =~ '^35[0-9][0-9]')
  {
    cbi = 'CSCvi99250';
    vuln_ranges = [
      { 'min_ver' : '0', 'fix_ver' : '6.0(2)A8(11)'},
      { 'min_ver' : '7.0', 'fix_ver' : '7.0(3)I7(3)'}
    ];
  }
  else if (product_info.model =~ '^36[0-9][0-9]|95[0-9][0-9](-FM)?-R')
  {
    cbi = 'CSCvi99247';
    vuln_ranges = [
      { 'min_ver' : '7.0', 'fix_ver' : '9.2(1)' }
    ];
  }
  else if (product_info.model =~ '^7[07][0-9][0-9]')
  {
    cbi = 'CSCvi99248';
    vuln_ranges = [
      { 'min_ver' : '0', 'fix_ver' : '6.2(22)' },
      { 'min_ver' : '7.2', 'fix_ver' : '7.3(3)D1(1)' },
      { 'min_ver' : '8.0', 'fix_ver' : '8.2(3)' },
      { 'min_ver' : '8.3', 'fix_ver' : '8.3(2)' }
    ];
  }
  else if (product_info.model =~ '^(55|56|60)[0-9][0-9]')
  {
    cbi = 'CSCvi99251';
    vuln_ranges = [
      { 'min_ver' : '0', 'fix_ver' : '7.3(4)N1(1)' }
    ];
  }
}
else if('UCS' >< product_info.device && product_info.model =~ '^6[234][0-9][0-9]')
{
  cbi = 'CSCvi99252 and CSCvn11851';
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '4.0(1d)' }
  ];
}

if (cbi == '') 
  audit(AUDIT_HOST_NOT, 'affected');


var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
