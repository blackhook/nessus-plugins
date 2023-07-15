#TRUSTED 5872a8d5f0de7f9a016026be4696a601553ad4c875268128df5f2a3b9ef5d3d612ed6375b91c42326a39f7f6640a56586c7efd663e0f9734eb3b98ddd78886fc957e85e5fe33996b82b709bbf34cb75e2b72508c1ea5be0ee91d6e1b4a798bd2bb853f8031384451f5b190929c1db7e1ee4f480911aca26958f37511869b93aeb7f8ca5d86bb59c909d0eef172f185bc5a805e9e8218cbd97e58f3a64abd2a91e7fca41b16c9743f766d91bec527bf4b8f54e06e8ee7d43950c59646d0bf98fd4636a3bb4df787f0232be06cf473c403f1f7dc947be85732ee6b8a7db558d3ad7534aee7b5e5e5dcf87253dc1c5b6a5d5969298a4f43af3b7883f492d35450a8a82602693871fcb67b544c6200853e424b753f07619cb0947b8b8b1c369c7fd98fb7996436eb8aa8042a42c306dfa8ac06f4bcd0dd8c49e57904390fb1db13db62f305a8cf59f704d3847dd5c23c8866694e97b405254d43a7222a3a747d4312f3e45c3a1a2e07f0cadc5597ef22332bbdc2a8ee65dd56c4bf860c2a1cee1e8264f1480956f21f40e803165b6c0a694cbd50da93b46a720806cbfb85d8d8c6b0ea61eaaa52b52d42b1e9c0ea8c60f98cf500ca5180ecd2ea7f30d7b06ac35cc8f29644e4b894804a85211a3e24b3dab0ff040c578cc261ee0e2c82b195af8f6a5c76139ce87ff20537c193cf86dae3112ae18d21dcd8aad3cb8807a2e46a2f1d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158208);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/22");

  script_cve_id("CVE-2021-1586");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw87983");
  script_xref(name:"CISCO-SA", value:"cisco-sa-n9kaci-tcp-dos-YXukt6gM");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches ACI Mode Multi-Pod Multi-Site TCP DoS (cisco-sa-n9kaci-tcp-dos-YXukt6gM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software in ACI Mode is affected by a denial of service 
vulnerability. The vulnerability exists in Application Centric Infrastructure (ACI) mode of Multi-Pod or Multi-Site 
network configurations for Cisco Nexus 9000 Series Fabric Switches. An unauthenticated, remote attacker can exploit 
this by sending specially crafted TCP data to a specific port which listens on a public-facing IP address configured 
for both Multi-Pod or Multi-Site resulting in system to reboot unexpectedly and cause a DoS condition.

Cisco has released software updates that address this vulnerability. There are no workarounds that address this vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9kaci-tcp-dos-YXukt6gM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee7bb5d5");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74640");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw87983");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw87983");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1586");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(345);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Host/aci/system/chassis/summary");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,}")
  audit(AUDIT_HOST_NOT, 'an affected model');

# 9k in ACI mode
if (empty_or_null(get_kb_list('Host/aci/*')))
  audit(AUDIT_HOST_NOT, 'an affected model due to non ACI mode');

# Not checking for config
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco NX-OS');

var version_list = make_list(
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
  '11.0(4h)',
  '11.0(4o)',
  '11.0(4q)',
  '11.0(4g)',
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
  '11.2(2g)',
  '11.2(3c)',
  '11.2(2h)',
  '11.2(2i)',
  '11.2(3e)',
  '11.2(3h)',
  '11.2(3m)',
  '11.2(1k)',
  '11.2(1m)',
  '11.2(2j)',
  '12.0(1m)',
  '12.0(2g)',
  '12.0(1n)',
  '12.0(1o)',
  '12.0(1p)',
  '12.0(1q)',
  '12.0(2h)',
  '12.0(2l)',
  '12.0(2m)',
  '12.0(2n)',
  '12.0(2o)',
  '12.0(2f)',
  '12.0(1r)',
  '12.1(1h)',
  '12.1(2e)',
  '12.1(3g)',
  '12.1(4a)',
  '12.1(1i)',
  '12.1(2g)',
  '12.1(2k)',
  '12.1(3h)',
  '12.1(3j)',
  '12.2(1n)',
  '12.2(2e)',
  '12.2(3j)',
  '12.2(4f)',
  '12.2(4p)',
  '12.2(3p)',
  '12.2(3r)',
  '12.2(3s)',
  '12.2(3t)',
  '12.2(2f)',
  '12.2(2i)',
  '12.2(2j)',
  '12.2(2k)',
  '12.2(2q)',
  '12.2(1o)',
  '12.2(4q)',
  '12.2(4r)',
  '12.2(1k)',
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
  '13.2(3n)',
  '13.2(3o)',
  '13.2(3r)',
  '13.2(4d)',
  '13.2(4e)',
  '13.2(3j)',
  '13.2(3s)',
  '13.2(5d)',
  '13.2(5e)',
  '13.2(5f)',
  '13.2(6i)',
  '13.2(41d)',
  '13.2(7f)',
  '13.2(7k)',
  '13.2(9b)',
  '13.2(8d)',
  '13.2(9f)',
  '13.2(9h)',
  '11.3(1g)',
  '11.3(2f)',
  '11.3(1h)',
  '11.3(1i)',
  '11.3(2h)',
  '11.3(2i)',
  '11.3(2k)',
  '11.3(1j)',
  '11.3(2j)',
  '14.0(1h)',
  '14.0(2c)',
  '14.0(3d)',
  '14.0(3c)',
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
  '14.2(5l)',
  '14.2(5n)',
  '14.2(6d)',
  '14.2(6g)',
  '14.2(6h)',
  '14.2(6l)',
  '14.2(6o)',
  '15.0(1k)',
  '15.0(1l)',
  '15.0(2e)',
  '15.0(2h)',
  '15.1(1h)',
  '15.1(2e)'
);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvw87983',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
