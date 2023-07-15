#TRUSTED 104c20edd05b0d18f985c0d82b329c6b4db0cb15a6d82fe6cfefe931e5caab681db70d3ab1ccb3d6bc1dc5288943f74ad53838d0a5ce2f701866892f3622cebfa13010d9d1f05cf394bd3f30fd1284074cf63261e683583565f7c231d2ddb761ef5b1e919342e9d33fed411dbaad2d05efc91ee14995a16deb9df0a992ff89b666d477b461d7a10ccb993a09f4fb3f14df62daa079524bf8a55abf74161eff1a134d3c66ee15285b158125faf8ef3f78b490be370d9c000d4aeac9e82943278af0301898942bcacd2ec1ab75229e14fd8c116551d00276c3c08f88eff3af44904ae70bd2f024c6faea4e58b812dcb31a082e0d0d3e3c3b5b440576eeacd26971b6d43b00b3d55d51f6e21896380e68ad50dda7063faffcc580c270ee924190d0ccb7a375748d319fea945965af417334c6607487feea7636c0f4d5d70fa697190e051c7341a9c8704fc6810740668949165827ff3806cdb61f67214c8bf257ef43a3542553a707fd4cd0ffed5e7612f7882d3bbb38bb98465082bc62c6a4ebf6b2835158c512873e54152c6b883effa1bd8e0f1063d9144909de532b23f4cf775d1317140c07d9eebfb924963ff12045ccb3598010661aec53c93a45899b778a63f5962d7ac866f43c89b6dae406be66d8e0b6291f988423a3249aa5d3916acd7a5aab4fccdcf1cdb15ded417f3d8efb790b367245e969aa978f59a39649a5fb
#TRUST-RSA-SHA256 512a25f24a9b6dbb22d939cf3f6797d2bb4fa8d797fdbc7aa383bf96bef892d8979802575ebcda3a56c1dc5394651d54ef085a6ea75f51f88b74b8a7f9e32428ea3fc369da69ab11500ea7fff23ea62988a9165274ce9508d4036863bd4c0def4a3ef511543dc795e0dbe9a8fbf8d6aad71ed45a5e478ecd16a659746aa0b1835bb40b55f64fa88fd02edb64be7109040f47f4cd14472d40ceddd76d627a74540599847af63810b24ed7a3ef1bbdcf1590dcb52fa7eacd045e927962cea98b72a101aba02994590a30e4c9cee2f5905b4131c080172aa67a3ccb23a8875cabaf0b8c02d991090c58eeee080a707424695fe6415fd4018a4b3fbd993ed9193e2eaa30158bb1f9e7204d5d6a113d91545ca6b8e025e194b7ddedb9b30a93d144bb30bc243696d11bad74d978247677df5fbf937e00ec58a87fcf230735e7468b248c3505276c4805752f08d6f75ff8c9bcec6c0da56d3e50f30cd554204b11012a0057dcd3c72d4318bfa8ef250ff5cda24666343d6a1a58c5e7e7da863791fffeb0a47f165337e9aa6d29e7753daca1c366d5538c859cae1515067d7c0f02ad2be39cee71677df22f52954bcdc962ff5675722b6eef533493068c5ae96fffb1515f46f59bfcd7382a0f210e76baa5e6d028fe3cb9a76a6644615c4c5bf9de4befc02bb3f54b52420dc36e66be793d76ac0978b52855efeefd116378b21d89e587
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173737);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/03");

  script_cve_id("CVE-2023-20049");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc39336");
  script_xref(name:"CISCO-SA", value:"cisco-sa-bfd-XmRescbT");
  script_xref(name:"IAVA", value:"2023-A-0126");

  script_name(english:"Cisco IOS XR Software for ASR 9000 Series Routers Bidirectional Forwarding Detection DoS (cisco-sa-bfd-XmRescbT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bfd-XmRescbT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50e462c3");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74917
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6d11e40");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc39336");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc39336");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
var smus = {};

# Vulnerable model list
if ('ASR' >!< model || model !~ "9[0-9]+|9902|9903")
    audit(AUDIT_HOST_NOT, 'affected');

if ('ASR9K-X64' >< model)
{
    smus['7.1.3'] = 'CSCwc39336';
    smus['7.3.2'] = 'CSCwc39336';
    smus['7.5.2'] = 'CSCwc39336';
}

var vuln_ranges = [
  {'min_ver' : '6.5', 'fix_ver' : '7.5.3'},
  {'min_ver' : '7.6', 'fix_ver' : '7.6.2'},
  {'min_ver' : '7.7', 'fix_ver' : '7.7.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['bfd_enabled_in_hw-offload_state'],
  WORKAROUND_CONFIG['bfd_enabled_in_all_session'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwc39336'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
