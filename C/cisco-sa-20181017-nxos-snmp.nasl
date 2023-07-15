#TRUSTED b2f12d34092f67a7f4e32a7ebb84862c0b6868ed4d3f62c6fcdbc23517d7a3e16bbe2c7cc311749204bffb5cbf1162d52f15e1eaab31322f57cdae66e9f2d9f1d51f76d8e1e7675306c9deec951106b4740047d294374dabd73646b8024542971c3ed7bb87406532a6db82e4e85a7e8f090117dd6a8e06d78ae050f054f5535fdd59ae8b8d27c17a4856cbab79d9cef2819a1f2ee40330941e5ca1a8925dbc78295a53f3c727e687ff1317316cd6443002390b34f3f8993c8d75d74a7f83c9279c683b3ce70473d05fdb9743b2d99f09fff6467ea23b8d99897485ec65aac619534266f66f7c12a29d002f915ed93bcb82dd4cd21c67b112ea399c81babdb3bf385d7f4c042dc64cbdd22887bdef320685780941de28faa7f15751dda63c50c59cb74f29fb0c7762fcd753b619f635866a5c693559f33e226770ff78a4ad7425894c6d86cdfa09b294f2b6a4d7d7e2cce9bb33e6522a4fa7dbb536e0403e22c8099d2f09e4f71aa9f2cd4642db9415fa64631d86ebbed7a97add7258e0b27bee44792349ebdc132726cd6ecc6996ac21f0c56d3b31d5ee9940f928d6595f0e34929ac0f4470fe1030bf3b41c8a85a3fc1c6437a97d11ef0cebb974692fd6dd7f688ba25380ef01ae5f6dc0d297490d2c051ee701bffee8c563fa79b40ab60c34b625114dd2a065a0a7574000a85f3ae025d7e6912e5012c09c5c1567165a5ea5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118462);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2018-0456");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj70029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-nxos-snmp");
  script_xref(name:"IAVA", value:"2018-A-0349");

  script_name(english:"Cisco NX-OS SNMP DoS.");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is
affected by a denial of service vulnerability due to improper
validation of SNMP protocol data. A remote authenticated attacker,
using a specially crafted SNMP packet, can cause the SNMP application
to restart resulting in a DoS condition. Please see the included Cisco
BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-nxos-snmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86310ecc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj70029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed / recommended version referenced in Cisco Security
Advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0456");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco NX-OS Software");

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^[39]0[0-9][0-9]')
  {
    vuln_list = make_list('7.0(3)I7(3)');
  }
  else if (product_info.model =~ '^(36|95)[0-9][0-9]')
  {
    vuln_list = make_list('7.0(3)F3(4)');
  }
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj70029'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:vuln_list);
