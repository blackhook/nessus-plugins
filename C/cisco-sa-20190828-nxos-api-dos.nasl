#TRUSTED 8e40806fe665557c2a7d17ae936e1b291665adf00b36fd34b22961280193b18223695ab27a84a18891251e4239394ea610769e394d40cc48ff66d4cbff22de98ffe4187f82e204af27d1eb880aff101b1b4937554f582106dbda5692cf99cdca2746ae71325207a5c6cf1563925eeb745d8cd16a52c4de9d16b4a2a5a2da7c4210b9d0acd79a14886bd10befaf931b059c4fa3945a4f0e4821b5473564aa6757f40c978456cb14dbc6e98f1900e9211bc6df7367c101b2d8c3a4d47a9858bc8f3597560d06a7fcc0915007a9965905c30e43deb549dc0d248c871d6e48d64bd0be5997d36aa2c6dfe21db4cdf938b8c72008426be0a435202a25c8db3d4f9c156dbc4069eccd8b98efa606273a46a9e9d79a1d5aeb4a8c9afaa9401fcb262437fd262efad30bba7dba6f18c069b2c7049f308bc3a043f83f8f60b8f19f72e9474168006c5e7d92a99bd6b6259a46c103391a65e42397239a86fd7c7c66d4cf65d6358d0eb58e26bc088075835416201ee176ca6c540ee6097d88dcd4992007e5f3b067b867d0b94f3fd2857d9588d277864ff9f72a7956c44dfbc5e1cc06eaf1fe29fae9f36b9f8ab5b400979929ce7a998fb61e73ff1f5b7192e5a2688cdd204aa07764c5b5472408202f6eca089153eff3d70566f407a8192b850fa65f3dc217637dad3cd2353dfd4b2a5d088c9413810dca48ac1275aa83cefe62a2bbc5a3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128550);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2019-1968");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn26502");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn31273");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn57900");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-nxos-api-dos");
  script_xref(name:"IAVA", value:"2019-A-0317");

  script_name(english:"Cisco NX-OS Software NX-API Denial of Service Vulnerability (CVE-2019-1968)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service vulnerability in the
NX-API of Cisco NX-OS Software due to incorrect validation of HTTP requests. An unauthenticated, remote attacker could
exploit this, by sending a crafted HTTP request to the NX-API, to cause a denial of service condition in the NX-API
service.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-nxos-api-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a91dc821");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn31273");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn57900");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn26502");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvn2650, CSCvn31273 and CSCvn57900");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = 'CSCvn26502';
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvn26502';
  else if (product_info.model =~ '^(5[56]|60)[0-9][0-9]')
    cbi = 'CSCvn57900';
  else if (product_info.model =~ '^(3[056]|9[05])[0-9][0-9]')
    cbi = 'CSCvn31273';
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '6.0(2)A4(1)',
  '6.0(2)A4(2)',
  '6.0(2)A4(3)',
  '6.0(2)A4(4)',
  '6.0(2)A4(5)',
  '6.0(2)A4(6)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(6)',
  '6.0(2)A6(7)',
  '6.0(2)A6(8)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8(10)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(11)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)U4(1)',
  '6.0(2)U4(2)',
  '6.0(2)U4(3)',
  '6.0(2)U4(4)',
  '6.0(2)U5(1)',
  '6.0(2)U5(2)',
  '6.0(2)U5(3)',
  '6.0(2)U5(4)',
  '6.0(2)U6(10)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(9)',
  '6.1(2)I2(2a)',
  '6.1(2)I2(2b)',
  '6.1(2)I2(3)',
  '6.1(2)I3(1)',
  '6.1(2)I3(2)',
  '6.1(2)I3(3)',
  '6.1(2)I3(3a)',
  '6.1(2)I3(4)',
  '6.1(2)I3(4a)',
  '6.1(2)I3(4b)',
  '6.1(2)I3(4c)',
  '6.1(2)I3(4d)',
  '6.1(2)I3(4e)',
  '6.1(2)I3(5)',
  '6.1(2)I3(5b)',
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(4)',
  '7.0(3)F3(5)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1z)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2r)',
  '7.0(3)I2(2s)',
  '7.0(3)I2(2v)',
  '7.0(3)I2(2w)',
  '7.0(3)I2(2x)',
  '7.0(3)I2(2y)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(1t)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(6t)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(3)',
  '7.0(3)I5(3a)',
  '7.0(3)I5(3b)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)I7(3z)',
  '7.0(3)I7(4)',
  '7.0(3)I7(5)',
  '7.0(3)I7(5a)',
  '7.0(3)IA7(1)',
  '7.0(3)IA7(2)',
  '7.0(3)IC4(4)',
  '7.0(3)IM3(1)',
  '7.0(3)IM3(2)',
  '7.0(3)IM3(2a)',
  '7.0(3)IM3(2b)',
  '7.0(3)IM3(3)',
  '7.0(3)IM7(2)',
  '7.0(3)IX1(2)',
  '7.0(3)IX1(2a)',
  '7.1(0)N1(1)',
  '7.1(0)N1(1a)',
  '7.1(0)N1(1b)',
  '7.1(1)N1(1)',
  '7.1(1)N1(1a)',
  '7.1(2)N1(1)',
  '7.1(2)N1(1a)',
  '7.1(3)N1(1)',
  '7.1(3)N1(2)',
  '7.1(3)N1(2a)',
  '7.1(3)N1(3)',
  '7.1(3)N1(4)',
  '7.1(3)N1(5)',
  '7.1(4)N1(1)',
  '7.1(4)N1(1a)',
  '7.1(4)N1(1c)',
  '7.1(4)N1(1d)',
  '7.1(5)N1(1)',
  '7.1(5)N1(1b)',
  '7.2(0)D1(1)',
  '7.2(0)N1(1)',
  '7.2(1)D1(1)',
  '7.2(1)N1(1)',
  '7.2(2)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(3)',
  '7.2(2)D1(4)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)N1(1)',
  '7.3(0)N1(1a)',
  '7.3(0)N1(1b)',
  '7.3(1)D1(1)',
  '7.3(1)N1(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(2)N1(1)',
  '7.3(2)N1(1b)',
  '7.3(2)N1(1c)',
  '7.3(3)D1(1)',
  '7.3(3)N1(1)',
  '7.3(4)N1(1)',
  '7.3(4)N1(1a)',
  '8.0(1)',
  '8.1(1)',
  '8.1(1a)',
  '8.1(1b)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)',
  '8.3(1)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)'
);


workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_nxapi'];

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
