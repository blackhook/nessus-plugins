#TRUSTED 93425f3bf89ae39d6467894b0530965ff5aaf9dfad29e729e21d1db012dd0a6257c715df1a9d94b546f509e3d45ff50baf2dcf5c69d4ccfb31605ae5e2c186a2efbbd5b661f2512cc2a3776e3fceda1946dc86fc512a4c72b89f181b243c2ed9a89a03aa411c0a4178c6fb9a11752a7892a787b7c59a998d209578013c1ee6d4e0d7029d2aaee2dd10bebee83b6cc27f0323dfe9a88518cd844f63ab3176266fa4623b2fa0f1b2de3a4bff5fc8d3fc561b6a257759bf010b8513f609b16ec009d6728758d92f5448c01ae739ffac8a2a90bd57ddfe95ffaf266d0d1c19c9bc58f67c98d83f5700a85a6c94ba9454db9035307f917ce5bd55f3277e34b3d552850258bc07bfcbe6484a9f0633cbee60c1bdeb2974df96e3076663f422bcc04103cc09ce31c2e4530275c64471c602eabb452e41b7cee4fe37af707f000135400a972d442980d89acee0da98e9a86d54750557051d0eda63343bedc527703d528035e0cde4bcc74a177900a1fed1199d65dd6337ef562b24b23e73c25685ab6d0e74f0b28c818b3a6685b97539ca368f6997906added97961fb56c70a5c4ea753dc812c52866f7de7952fba9773f191b1dbf251c4d8f9ff8cdb9aa83734b566554317e5ed1b88431c819087ba9d95a07d04cbb8bd30fd645ed0a0302338c2b14c16497335a47fa3f89fa46879fde8ce1b5060457c2e6694cfd932806da0b2297ae
#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(139922);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/02");

  script_cve_id("CVE-2020-3338");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr91853");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr97684");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-pim-memleak-dos-tC8eP7uw");
  script_xref(name:"IAVA", value:"2020-A-0394");

  script_name(english:"Cisco NX-OS Software IPv6 Protocol Independent Multicast DoS (cisco-sa-nxos-pim-memleak-dos-tC8eP7uw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service (DoS) vulnerability due
to improper error handling when processing inbound PIM6 packets. An unauthenticated, remote attacker can exploit this,
by sending multiple crafted PIM6 packets to an affected device, in order to cause the PIM6 application to leak system
memory and stop processing legitimate PIM6 traffic, leading to a DoS condition on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-pim-memleak-dos-tC8eP7uw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?319c006d");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr91853");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr97684");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr91853, CSCvr97684");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3338");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(404);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "^[379][0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

#  not 9k in ACI mode
if (!(empty_or_null(get_kb_list('Host/aci/*'))))
    audit(AUDIT_HOST_NOT, 'an affected model due to ACI mode');

if (product_info.model =~ "^[39][0-9]{3}")
  cbi = 'CSCvr91853';
else
  cbi = 'CSCvr97684';

version_list=make_list(
  '5.0(3)A1(1)',
  '5.0(3)A1(2)',
  '5.0(3)A1(2a)',
  '5.0(3)U1(1)',
  '5.0(3)U1(1a)',
  '5.0(3)U1(1b)',
  '5.0(3)U1(1c)',
  '5.0(3)U1(1d)',
  '5.0(3)U1(2)',
  '5.0(3)U1(2a)',
  '5.0(3)U2(1)',
  '5.0(3)U2(2)',
  '5.0(3)U2(2a)',
  '5.0(3)U2(2b)',
  '5.0(3)U2(2c)',
  '5.0(3)U2(2d)',
  '5.0(3)U3(1)',
  '5.0(3)U3(2)',
  '5.0(3)U3(2a)',
  '5.0(3)U3(2b)',
  '5.0(3)U4(1)',
  '5.0(3)U5(1)',
  '5.0(3)U5(1a)',
  '5.0(3)U5(1b)',
  '5.0(3)U5(1c)',
  '5.0(3)U5(1d)',
  '5.0(3)U5(1e)',
  '5.0(3)U5(1f)',
  '5.0(3)U5(1g)',
  '5.0(3)U5(1h)',
  '5.0(3)U5(1i)',
  '5.0(3)U5(1j)',
  '5.2(1)',
  '5.2(3)',
  '5.2(3a)',
  '5.2(4)',
  '5.2(5)',
  '5.2(7)',
  '5.2(9)',
  '5.2(9a)',
  '6.0(2)A1(1)',
  '6.0(2)A1(1a)',
  '6.0(2)A1(1b)',
  '6.0(2)A1(1c)',
  '6.0(2)A1(1d)',
  '6.0(2)A1(1e)',
  '6.0(2)A1(1f)',
  '6.0(2)A1(2d)',
  '6.0(2)A3(1)',
  '6.0(2)A3(2)',
  '6.0(2)A3(4)',
  '6.0(2)A4(1)',
  '6.0(2)A4(2)',
  '6.0(2)A4(3)',
  '6.0(2)A4(4)',
  '6.0(2)A4(5)',
  '6.0(2)A4(6)',
  '6.0(2)A6(1)',
  '6.0(2)A6(1a)',
  '6.0(2)A6(2)',
  '6.0(2)A6(2a)',
  '6.0(2)A6(3)',
  '6.0(2)A6(3a)',
  '6.0(2)A6(4)',
  '6.0(2)A6(4a)',
  '6.0(2)A6(5)',
  '6.0(2)A6(5a)',
  '6.0(2)A6(5b)',
  '6.0(2)A6(6)',
  '6.0(2)A6(7)',
  '6.0(2)A6(8)',
  '6.0(2)A7(1)',
  '6.0(2)A7(1a)',
  '6.0(2)A7(2)',
  '6.0(2)A7(2a)',
  '6.0(2)A8(1)',
  '6.0(2)A8(10)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(11)',
  '6.0(2)A8(11a)',
  '6.0(2)A8(11b)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)U1(1)',
  '6.0(2)U1(1a)',
  '6.0(2)U1(2)',
  '6.0(2)U1(3)',
  '6.0(2)U1(4)',
  '6.0(2)U2(1)',
  '6.0(2)U2(2)',
  '6.0(2)U2(3)',
  '6.0(2)U2(4)',
  '6.0(2)U2(5)',
  '6.0(2)U2(6)',
  '6.0(2)U3(1)',
  '6.0(2)U3(2)',
  '6.0(2)U3(3)',
  '6.0(2)U3(4)',
  '6.0(2)U3(5)',
  '6.0(2)U3(6)',
  '6.0(2)U3(7)',
  '6.0(2)U3(8)',
  '6.0(2)U3(9)',
  '6.0(2)U4(1)',
  '6.0(2)U4(2)',
  '6.0(2)U4(3)',
  '6.0(2)U4(4)',
  '6.0(2)U5(1)',
  '6.0(2)U5(2)',
  '6.0(2)U5(3)',
  '6.0(2)U5(4)',
  '6.0(2)U6(1)',
  '6.0(2)U6(10)',
  '6.0(2)U6(10a)',
  '6.0(2)U6(1a)',
  '6.0(2)U6(2)',
  '6.0(2)U6(2a)',
  '6.0(2)U6(3)',
  '6.0(2)U6(3a)',
  '6.0(2)U6(4)',
  '6.0(2)U6(4a)',
  '6.0(2)U6(5)',
  '6.0(2)U6(5a)',
  '6.0(2)U6(5b)',
  '6.0(2)U6(5c)',
  '6.0(2)U6(6)',
  '6.0(2)U6(7)',
  '6.0(2)U6(8)',
  '6.0(2)U6(9)',
  '6.1(2)I1(2)',
  '6.1(2)I1(3)',
  '6.1(2)I2(1)',
  '6.1(2)I2(2)',
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
  '6.1(2)I3(5a)',
  '6.1(2)I3(5b)',
  '6.2(10)',
  '6.2(12)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(14b)',
  '6.2(16)',
  '6.2(18)',
  '6.2(2)',
  '6.2(20)',
  '6.2(20a)',
  '6.2(22)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6a)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
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
  '7.0(3)I2(1)',
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
  '7.0(3)I4(8z)',
  '7.0(3)I4(9)',
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
  '7.0(3)I7(6)',
  '7.0(3)I7(6z)',
  '7.0(3)I7(7)',
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
  '7.2(0)D1(1)',
  '7.2(1)D1(1)',
  '7.2(2)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(3)',
  '7.2(2)D1(4)',
  '7.3(0)D1(1)',
  '7.3(0)DX(1)',
  '7.3(1)D1(1)',
  '7.3(2)D1(1)',
  '7.3(2)D1(1d)',
  '7.3(2)D1(2)',
  '7.3(2)D1(3)',
  '7.3(2)D1(3a)',
  '7.3(3)D1(1)',
  '7.3(4)D1(1)',
  '7.3(5)D1(1)',
  '8.0(1)',
  '8.1(1)',
  '8.1(2)',
  '8.1(2a)',
  '8.2(1)',
  '8.2(2)',
  '8.2(3)',
  '8.2(4)',
  '8.2(5)',
  '8.3(1)',
  '8.3(2)',
  '8.4(1)',
  '9.2(1)',
  '9.2(2)',
  '9.2(2t)',
  '9.2(2v)',
  '9.2(3)',
  '9.2(3y)',
  '9.2(4)',
  '9.3(1)',
  '9.3(1z)',
  '9.3(2)'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config')
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['feature_pim6'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
