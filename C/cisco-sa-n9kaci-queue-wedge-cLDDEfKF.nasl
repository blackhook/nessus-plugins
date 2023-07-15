#TRUSTED 4d68d7c14bda919248fa39640ed2a5604627d48641c352f5eb1ea61569de9f666f95dbffe51a3cd936d8a1bb1cfe9868abbd209c2d67d502392e7c58d777910bed8332a9facfef783b0edac1b59a60c46ad1a607897af432b53eb951952fecaf3239a950688518d433177b532d38b0aed130fcaa4024c555991575bab1e64b55cc9ab8cba5aede4470329dd3b8316b88b96ae9ab3b86c558aea7eda4365235a8e9ef87c86ca93cfb88e226d7073f8ef8f26d9c1262e4bdf224728391fbf77a12e795b7a01487411ca53104aa4200d6ba30be99928d662d1635cc25ed54a1c0d45e4bec891b90dd17a55b25ea9db6894660580c32188af07a27bbd0afa015e98ec82545e6fe5665aa283342dcbb7512148b2b8066534a074e6232999b3a7a7f783e0fed7ee2158f973772a384aec3bc1e07a7b952395a8c9f2c059f3567dadff36d56fad1510e162549be46b35d0e8b08ecd9b368e2aa9d26922eb7eb4caf1713f873b0f1378dd6d747419f40e7de130a57c0f1759cf2ba541f09c88fca4161bd1d25b19459ee75f32a8e0cf28136fc33bfb7ecb3ee31d45e2d4a626576d433fe71bd4dd0124c67377eff5529d04ab53a54245785f56d4b5bec05b01511412f82cd4ce697dd3345546fc15f40afd5698b67c779458334073bdd9db3e990e73b9db9dc83bcb39f6e2648d296723b5c0fe9bd57877a93642d149d460c8c440418e4
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158207);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/22");

  script_cve_id("CVE-2021-1523");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx14142");
  script_xref(name:"CISCO-SA", value:"cisco-sa-n9kaci-queue-wedge-cLDDEfKF");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches ACI Mode Queue Wedge DoS (cisco-sa-n9kaci-queue-wedge-cLDDEfKF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software in ACI Mode is affected by a denial of service 
vulnerability. The vulnerability exists in Cisco Nexus 9000 Series Fabric Switches in Application Centric Infrastructure (ACI) mode.
An unauthenticated, remote attacker can exploit this by sending a stream of TCP packets to a specific port on a 
Switched Virtual Interface (SVI) configured on the device to cause a specific packet queue to queue network buffers 
but never process them, leading to an eventual queue wedge. This could cause control plane traffic to be dropped, 
resulting in a denial of service (DoS) condition where the leaf switches are unavailable.

Note: This vulnerability requires a manual intervention to power-cycle the device to recover.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9kaci-queue-wedge-cLDDEfKF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c4051f9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74640");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx14142");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx14142");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1523");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(772);

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

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{3,}")
  audit(AUDIT_HOST_NOT, 'affected');

#  9k in ACI mode
if (empty_or_null(get_kb_list('Host/aci/*')))
  audit(AUDIT_HOST_NOT, 'an affected model due to non ACI mode');

var g_model = cisco_command_kb_item('Host/Cisco/Config/show_inventory', 'show inventory');
if (empty_or_null(g_model))
  audit(AUDIT_HOST_NOT, 'an affected model');

var model_list = make_list(
  'N9K-C9372PX-E',
  'N9K-C9372TX-E',
  'N9K-C9332PQ',
  'N9K-C9372PX',
  'N9K-C9372TX',
  'N9K-C9396PX',
  'N9K-C9396TX',
  'N9K-C93128TX',
  'N9K-C93120TX'
);

var vuln_model = FALSE;
foreach g1_model (model_list)
{
  if (g1_model >< g_model)
  {
    vuln_model = TRUE;
    break;
  }
}

if (!vuln_model)
  audit(AUDIT_HOST_NOT, 'an affected generation 1 model');

var version_list = make_list(
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
  '14.2(6o)'
);

var reporting = make_array(
  'port', 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'cmds'    , make_list('show inventory'),
  'bug_id'  , 'CSCvx14142'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);