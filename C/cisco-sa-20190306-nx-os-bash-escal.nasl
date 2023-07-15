#TRUSTED 2deef25ab02f2f601458d80517dba065a07dceb59c521c0a4c06ac4e0c0c37509b3d1ce4af52e46218de4f02697309af2220ad2186c3ebcb16c5af2cd0029a3315b01aa811e6578a6c41010267006f4e80d8038d157ce95635dd957d359fbc96c998b2fae8ecf32ce1f02553a38254589726653be74b6cb7e09fd08fb814177352ff5f756941ee0ef77686abe59821980b832fe2a67a5072aea374019c181de6be33855e157ec96a98bf89968107d3123095dd18df06bab1c3cf48b8ca4029d9301068aa80a39be02b884f8ae81e273e71fe9dabe6bfd02fb3140c4f3bc5d64306192f11d76091299a2172a23fab31cc49ac19bf0d57edcac142817441b8df84923474092c667472acc297d83330f40750ba8c38a74e2df614543037a582c0b9420fa5923c8a6c9ad2797513485788bcf55849ecfa17c2049c4ae9c5fbc84f56f5c529f72473a110d13b3af032b213f22502fbc52ff209b796b165c25849927e65ad9fe5bf494990b538e3f5fb88fa46a4d12c151540cf45941450f0dc72b406b900517b18b5d7950e676bc75de88dcd28066cde5b5912bce3a6ed8454ad0050b4bdf712f521555e3ec05204183eb3b5d9e3574cba39afcd9765857e6e7ea41dbc76317f495617189c746bb64c5be0337a1a825764bd56fb54674a9ebdf80890bf61b43631457ebb4e782bf6a729a00ad5ca250e3932b6c7fe0966bb7522295f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126509);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1593");
  script_bugtraq_id(107324);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj59431");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj59446");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52940");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk52941");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nx-os-bash-escal");

  script_name(english:"Cisco NX-OS Software Bash Shell Role-Based Access Control Bypass Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a bash shell implementation for Cisco NX-OS software is affected access
control bypass privilege vulnerability. An authenticated local attacker can escalate their privilege level by
executing commands authorized to other user roles.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nx-os-bash-escal
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b371e68a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj59431");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj59446");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52940");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk52941");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj59431, CSCvj59446, CSCvk52940, CSCvk52941");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1593");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
cbi = '';

version_list=make_list(
  '7.0(3)F1(1)',
  '7.0(3)F2(1)',
  '7.0(3)F2(2)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)I1(1)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(2)',
  '7.0(3)I1(3)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(3)',
  '7.0(3)I2(4)',
  '7.0(3)I2(5)',
  '7.0(3)I2(1)',
  '7.0(3)I3(1)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
  '7.0(3)I5(1)',
  '7.0(3)I5(2)',
  '7.0(3)I6(1)',
  '7.0(3)I6(2)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '7.0(3)IX1(2)',
  '7.0(3)IX1(2a)',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)'
);

if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^(3|9)')
    cbi = 'CSCvj59431, CSCvk52941, CSCvk52940';
  else if (product_info.model =~ '^7[07][0-9][0-9]')
    cbi = 'CSCvj59446';
}

if (empty_or_null(cbi))
  audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
