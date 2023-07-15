#TRUSTED 30c47820c62653420ff80f8031fefc31bb4abd0086cc9fc18cbebfb5c0c3975e1ef3508968074d24cfcf1e8998c3f463ec22842e4e1ec006faa68ca34b5525a5f0144dbaa14ad31378b49fc505710abc97c7eac6461fce9c857e2fa99a17a0a094e87a331737bdd2bf5b447accc65ba7341c17229136539926f80930d2a04b7dacc003b3d4ad11c2aa2a2334b94879236e054c8b7c3c3fe00d30b5d185e9b04b5851c18808be919184d5ba635e3014d4605e093deb323718d04a1767afb5b610b046c0fbe55a9bd183571808e1697421d86e13e160fb1e89c7ba6ddbd80984a80ab238a9b9027889cea0ff5a8a697efdb292ab167d90636adab22e4b60ec527f9e0ef9f5ac8d7a5ab7f899fe7cefb23238c4e313ce3f4ecad2dc579595c388f99c41636a5996113ff62e70701374dde6d60dc5d6f0a3a595be6c2c5c8e2031f0478c4c23152cb51fbfa2a89cfcea4c6b687d5b3427e821880231e4cd4f7e67ae7198b47c94840c0bfe5e619ca8d465307aebf5056e30b3041071bf25bee2148f527c22c7676532d796343db5a51e354f26dd35784508ca994edd1a9541d6454c24e7d814fda2db4d4db9b9044f383e03eb56b559639b45c34416740e3bbf076bfd3a13acb31324484dbdfd5f58f5d03c0b89b64b44f461003fadf7b1c532580d48ed374bc4e68c7f8905bfcaa95279375535cb140b475ef6799eaf00497e793d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151441);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id("CVE-2021-1231");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu84570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-apic-lldap-dos-WerV9CFj");
  script_xref(name:"IAVA", value:"2021-A-0113");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches ACI Mode Link Layer Discovery Protocol Port DoS (cisco-sa-apic-lldap-dos-WerV9CFj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service (DoS) vulnerability.
The vulnerability exists in the Link Layer Discovery Protocol (LLDP) due to incorrect processing of LLDP on packets on an SFP interface. 
An unauthenticated, adjacent attacker can exploit this issue, via sending a crafted LLDP packet, 
to cause the system to disable switching on the SFP interface.

Note that this vulnerability only affects systems in Application Centric Infrastructure (ACI) mode.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-lldap-dos-WerV9CFj
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?7105db36");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu84570");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu84570");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Host/aci/system/chassis/summary");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

# nexus
# 9000 series
# aci mode
if (
  'Nexus' >!< product_info.device ||
   product_info.model !~ '^90[0-9][0-9]' ||
   empty_or_null(get_kb_item("Host/aci/system/chassis/summary"))
)
  audit(AUDIT_HOST_NOT, 'affected');
  
var version_list=make_list(
  '11.0(1b)',
  '11.0(1c)',
  '11.0(1d)',
  '11.0(1e)',
  '11.0(2j)',
  '11.0(2m)',
  '11.0(3f)',
  '11.0(3i)',
  '11.0(3k)',
  '11.0(3n)',
  '11.0(3o)',
  '11.0(4g)',
  '11.0(4h)',
  '11.0(4o)',
  '11.0(4q)',
  '11.1(1j)',
  '11.1(1o)',
  '11.1(1r)',
  '11.1(1s)',
  '11.1(2h)',
  '11.1(2i)',
  '11.1(3f)',
  '11.1(4e)',
  '11.1(4f)',
  '11.1(4g)',
  '11.1(4i)',
  '11.1(4l)',
  '11.1(4m)',
  '11.2(1i)',
  '11.2(1k)',
  '11.2(1m)',
  '11.2(2g)',
  '11.2(2h)',
  '11.2(2i)',
  '11.2(2j)',
  '11.2(3c)',
  '11.2(3e)',
  '11.2(3h)',
  '11.2(3m)',
  '11.3(1g)',
  '11.3(1h)',
  '11.3(1i)',
  '11.3(1j)',
  '11.3(2f)',
  '11.3(2h)',
  '11.3(2i)',
  '11.3(2j)',
  '11.3(2k)',
  '12.0(1m)',
  '12.0(1n)',
  '12.0(1o)',
  '12.0(1p)',
  '12.0(1q)',
  '12.0(1r)',
  '12.0(2f)',
  '12.0(2g)',
  '12.0(2h)',
  '12.0(2l)',
  '12.0(2m)',
  '12.0(2n)',
  '12.0(2o)',
  '12.1(1h)',
  '12.1(1i)',
  '12.1(2e)',
  '12.1(2g)',
  '12.1(2k)',
  '12.1(3g)',
  '12.1(3h)',
  '12.1(3j)',
  '12.1(4a)',
  '12.2(1k)',
  '12.2(1n)',
  '12.2(1o)',
  '12.2(2e)',
  '12.2(2f)',
  '12.2(2i)',
  '12.2(2j)',
  '12.2(2k)',
  '12.2(2q)',
  '12.2(3j)',
  '12.2(3p)',
  '12.2(3r)',
  '12.2(3s)',
  '12.2(3t)',
  '12.2(4f)',
  '12.2(4p)',
  '12.2(4q)',
  '12.2(4r)',
  '12.3(1e)',
  '12.3(1f)',
  '12.3(1i)',
  '12.3(1l)',
  '12.3(1o)',
  '12.3(1p)',
  '13.0(1k)',
  '13.0(2h)',
  '13.0(2k)',
  '13.0(2n)',
  '13.1(1i)',
  '13.1(2m)',
  '13.1(2o)',
  '13.1(2p)',
  '13.1(2q)',
  '13.1(2s)',
  '13.1(2t)',
  '13.1(2u)',
  '13.1(2v)',
  '13.2(1l)',
  '13.2(1m)',
  '13.2(2l)',
  '13.2(2o)',
  '13.2(3i)',
  '13.2(3j)',
  '13.2(3n)',
  '13.2(3o)',
  '13.2(3r)',
  '13.2(3s)',
  '13.2(41d)',
  '13.2(4d)',
  '13.2(4e)',
  '13.2(5d)',
  '13.2(5e)',
  '13.2(5f)',
  '13.2(6i)',
  '13.2(7f)',
  '13.2(7k)',
  '13.2(8d)',
  '13.2(9b)',
  '13.2(9f)',
  '13.2(9h)',
  '14.0(1h)',
  '14.0(2c)',
  '14.0(3c)',
  '14.0(3d)',
  '14.1(1i)',
  '14.1(1j)',
  '14.1(1k)',
  '14.1(1l)',
  '14.1(2g)',
  '14.1(2m)',
  '14.1(2o)',
  '14.1(2s)',
  '14.1(2u)',
  '14.1(2w)',
  '14.1(2x)',
  '14.2(1i)',
  '14.2(1j)',
  '14.2(1l)',
  '14.2(2e)',
  '14.2(2f)',
  '14.2(2g)',
  '14.2(3j)',
  '14.2(3l)',
  '14.2(3n)',
  '14.2(3q)',
  '14.2(4i)',
  '14.2(4k)',
  '14.2(4o)',
  '14.2(4p)',
  '14.2(5k)',
  '15.0(1k)',
  '15.0(1l)',
  '15.0(2e)',
  '15.0(2h)'
);

var  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['sfp_interface_installed'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu84570',
  'cmds'     , make_list('show interface brief')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
