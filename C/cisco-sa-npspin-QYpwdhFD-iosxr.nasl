#TRUSTED 9657908470f8e7dec9e3ea7f866be93bbac4da9082d721f8cf1916c0d0734264b0845ca323599360fd512d4bd526944688b7bf4ff9bce4c494ac28cdf4c6a5d3cd5dd95f519fcbaa9fd01f40d683e1ba5201c1d46eb6b4c19b7a60178e31b3c0c5ef1c7c72228e1bf2a2cb3b6ad19e5ccbfe4a46bc35b6b98e8ec5d896486c72faf7ce873a4d0a5460636a5ffddcca983a408294edc43566c4d12d0751ba75ae774853dfebdb5c36a522cd1911a247ca7a19c0df9fa364d2ff6822495a3c611fa154c3564bbb91fad7c4e49b6677593ba2430455a2ae7189a98b6825d1a04e1228211c2ecf130df9e0bae03ef068ed910984ee9353f7ba7e6096854b4e79960d8420ada76f8fbfedce1d609646f34fccc015151ef660732eb2e676b39224087a9d68fadc73c1746ad64ea5abad33a66a5b061fa18e1adf44b27ab99349e437af0ef54ca6049cd58b08be508da5272d53532989d89b0e8fcbd2b92df58d633853b80db726fecc5eda1318f37c2112cf2bf2ecab5d55c18babb81f0de53921bcba049b0bffb9e045efaab0bf15cb402349f9291133739a60c40fb3fcb5f1ba9a4bbaa26d2d8ad940cd5b9fb926b70679c659299fbce4c85b9d1b3d32acb7281baa07d8003bad323e91d8f768d015a39ef63f96a46c6a759ee356bf0ea052bd300c3a9491354884fd0bd21f20ff364eb19c27e819bbc0507098cfb9d572039562ae
#TRUST-RSA-SHA256 26fa5280c3ab36151459f61d901e2eea9f81a4d72b8e320db0a700d5677feab40b75993cec8d7b0ddd55c314b197cfa3c61a5e7aa50b809edcd04e1d40f0e5a9594f9c2294a5f7c36108d3177415c4a7b538fba2bfee88d72ad5429be1a41123391e3c42af1c797927fd89a31d98bc00a759e42b17274a5e1d41a44c004f01d4560ddfb2b623a5648025f62576212c71416345006ea38eb4fa4150be2a20ca918cbab6d19720ed90854ca6fbc4274491747c79252a36d01c76402cf034ae265b7f9cefaf82a5a482628ae59cb8e7b794aeb1fbeb59b3b787291c2fb4d24199022cb002753797d98fa0ecc977cf5e4b12ffb8d3c25154eb65e6543361b84d594098a8fd89aae687976b70ce4aa5e49f883626776f09af2ddcc7de00c39e5cd3c708227b2ebd59813a46daba364a47a595daa6226821cb581fd54344b75fd605a6418a43b0005bdd65f368dfdb4bbef3062f4da632feaa1a90e283614336ea8eec5576dccc7cec6d317d0ee4ddb7e1cf82aad91dad3ed6fd08ae9ce6a14651da26cf0bdc45eff54f2e4b8a3849ddc8a9f16e34385512e03f8fd2b6f71beacc6297c66e4794de96bc07acb19a9f4f0dd6baea5715b895471521ef80d5198950f1b450f22254eb35057b8e09d9206e8aa0bbb9a633cada588e6df0bac26c2ea02d0563e0d26eba385fbdf3d9efa4440230795a02990aeae79ceeac7b1eb34ab6026c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156947);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");

  script_cve_id("CVE-2021-34713");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq33187");
  script_xref(name:"CISCO-SA", value:"cisco-sa-npspin-QYpwdhFD");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software for ASR 9000 Series Routers DoS (cisco-sa-npspin-QYpwdhFD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by denial of service vulnerability due to incorrect 
handling of specific Ethernet frames that cause a spin loop that can make the network processors unresponsive. An 
unauthenticated, adjacent attacker can exploit these by sending specific types of Ethernet frames on the segment where 
the affected line cards are attached. A successful exploit could allow the attacker to cause the affected line card to 
reboot.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-npspin-QYpwdhFD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0913a222");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq33187");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq33187");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model", "Host/Cisco/Config/show_platform");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');
var model = toupper(product_info.model);

var card_list = make_list(
  'A9K-1X100GE-SE',
  'A9K-1X100GE-TR',
  'A9K-24X10GE-SE',
  'A9K-24X10GE-TR',
  'A9K-2X100GE-SE',
  'A9K-2X100GE-TR',
  'A9K-36X10GE-SE',
  'A9K-36X10GE-TR',
  'A9K-40GE-SE',
  'A9K-40GE-TR',
  'A9K-4T16GE-SE',
  'A9K-4T16GE-TR',
  'A9K-MOD160-SE',
  'A9K-MOD160-TR',
  'A9K-MOD80-SE',
  'A9K-MOD80-TR',
  'A99-12X100GE',
  'A99-12X100GE-CM',
  'A99-48X10GE-1G-SE',
  'A99-48X10GE-1G-TR',
  'A99-8X100GE-CM',
  'A99-8X100GE-SE',
  'A99-8X100GE-TR',
  'A9K-24X10GE-1G-CM',
  'A9K-24X10GE-1G-SE',
  'A9K-24X10GE-1G-TR',
  'A9K-400G-DWDM-TR',
  'A9K-48X10GE-1G-CM',
  'A9K-48X10GE-1G-SE',
  'A9K-48X10GE-1G-TR',
  'A9K-4X100GE',
  'A9K-4X100GE-SE',
  'A9K-4X100GE-TR',
  'A9K-8X100GE-CM',
  'A9K-8X100GE-SE',
  'A9K-8X100GE-TR',
  'A9K-8X100G-LB-SE',
  'A9K-8X100G-LB-TR',
  'A9K-MOD200-SE',
  'A9K-MOD200-TR',
  'A9K-MOD400-CM',
  'A9K-MOD400-SE',
  'A9K-MOD400-TR'
);

var l_card = cisco_line_card(card_list:card_list);

if (empty_or_null(l_card))
  audit(AUDIT_HOST_NOT, 'an affected line card');

# Vulnerable model list
if (model !~ "ASR.{0,1}9.*")
{
  audit(AUDIT_HOST_NOT, 'affected model');
}

var smus = make_array();
if ('ASR9K-X64' >< model)
{
  smus['6.4.2'] = 'CSCvq33187';
  smus['6.5.3'] = 'CSCvq33187';
}
else if ('ASR9K-PX' >< model)
{
  smus['6.5.3'] = 'CSCvq33187';
}

var vuln_ranges = [
  {'min_ver': '6.4', 'fix_ver': '6.6.3'}, 
  {'min_ver': '6.7', 'fix_ver': '6.7.1'},
  {'min_ver': '7.0', 'fix_ver': '7.0.2'},
  {'min_ver': '7.1', 'fix_ver': '7.1.1'}
];

var reporting = make_array(
  'port'            , product_info['port'],
  'severity'        , SECURITY_WARNING,
  'bug_id'          , 'CSCvq33187',
  'version'         , product_info['version']
);

cisco::check_and_report(
  product_info      :product_info,
  reporting         :reporting,
  smus              :smus,
  vuln_ranges       :vuln_ranges
);
