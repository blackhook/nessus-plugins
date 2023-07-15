#TRUSTED 15c0709cf1b5be94ec5e556fb6ee1279a17860b14d1c0415f6872a6fa1952a2fc526bdf03e78afac27ac76377dd3905dd6a07c9b52b89ab57445147a479d0ad6fb509856dce66c3b5960574a49fa5179ea54452fea6cd0736f1b8794580a19203346fece39e3852d5cab8031df9b93a0f3a4a0070c07685fddbc117eea3cdb0414918725a2207669ac904f0984cde45d05e5289293c6b0aba2eb3aeb032348b68d4afac8d81ba94fb7b5c58b36f157603c18f26391f1f59d7ed1dabb77012ca7b3ab4a008bff2d3f2ad258bac4b360f9d85533aa7006fa5057e7a3449f99204e54dbfdc9db0e6b8b5602ab01b83506df98f9e161ffd04ce2f3a41692f09f099bfb06727f343f324e317c5f91b8c5ae749551202b7b58f4a21cca0a45ae568677444325b3b0bbc3f7a0e1ac08736d97a841c948215aba04056cf036b168005a972921a05c067cdaeba45d34884943556e234fb4aaca57a615d0e6b4f3fdf15e85be18daee432b9371e73966b0f2e73972e081cf89fbbf058abcf1ba096eaba5403ff59bf7115917ee8f8ecbad12c24251079638b62d6e24f027e1fb11607f0806be6d4b9c3c37f79132cb6491ab7872d5366de9bac40e7e9dc77e71d5b472ab81e1bc2137deb2154f37fe41ea2ae78a778a2cd6c639b3019ec91365123b29e5560bbcf71214f7d153341c4e6bf9cd6d467c27d557344100493e8ac60caebba6a0
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147649);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1136", "CVE-2021-1244");
  script_xref(name:"IAVA", value:"2021-A-0062-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr07463");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs70887");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ioxr-l-zNhcGCBt");

  script_name(english:"Cisco IOS XR Software for Cisco 8000 and NCS 540 Routers Image Verification Vulnerabilities (cisco-sa-ioxr-l-zNhcGCBt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR Software is affected by multiple vulnerabilities that allow
an authenticated, local attacker to execute unsigned code during the boot process, as follows:

   - A vulnerability in the GRUB boot loader of Cisco NCS 540 Series Routers, only when running Cisco IOS XR NCS540L
     software images, and Cisco IOS XR Software for the Cisco 8000 Series Routers could allow an authenticated, local
     attacker to execute unsigned code during the boot process on an affected device. (CVE-2021-1136)

   - A vulnerability in the signing functions of ISO packaging of Cisco NCS 540 Series Routers, only when running Cisco
     IOS XR NCS540L software images, and Cisco IOS XR Software for the Cisco 8000 Series Routers could allow an
     authenticated, local attacker with administrator privileges to execute unsigned code during the installation of an
     ISO on an affected device. (CVE-2021-1244)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ioxr-l-zNhcGCBt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee8a7f16");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr07463");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs70887");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr07463 and CSCvs70887.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

workarounds = make_list();
workaround_params = {};

# 8000 Series Router
if (model =~ "8[0-9]{3}")
{
  vuln_ranges = [
    {'min_ver' : '7.0', 'fix_ver' : '7.0.14'},
    {'min_ver' : '7.2', 'fix_ver' : '7.2.1'}
  ];
# NCS 540
}
else if (model =~ "NCS\s?540")
{
  vuln_ranges = [
    {'min_ver' : '7.0', 'fix_ver' : '7.2.1'}
  ];

  // NCS540 running NCS540L software image
  // vuln if LNT in 'show version' output
  workarounds = make_list(CISCO_WORKAROUNDS['show_version']);
  workaround_params = {'pat' : 'LNT'};
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected model');
}

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvr07463, CSCvs70887"
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);
