#TRUSTED 9b75573d280656a659a4a41418b5b57fb453ff4c2673a488ced6daee4b076e22226e48e42c227890f5cee1630c7c680c99d38540e183a34a64b72acbb0207516a7e78c432015abcc9b5287e53f6b4baee871c896019df9435c82f85ce1bebee66379659a6da51e6f5255e2dfde07f5bc37db16e483522dbf99f9881d28cf2350c0bb8b544fdeb1d99208d42913d129568f3cb388bffb47a3a96989da2aa58ffb1d993fd70c60dd1c5ba6a50b4d3729963b627101e3c0dfdb7ca97abdf1dd9ac509fc0c623618eb01145b9f8bac8caaf81550f3910e634491d5656d31053de30e308cc9b7f0d3745b1c93b2e850adb66efd01a2d3397fc19a708cbe04b1dcf36272f48de696e377d35e5c10ae63d39496874f24e73d47234ee49dc4a9d472da0917e5f4ecf66e2491b46f714f90797848b2a5b780dd184090ac1c0493daf9a61f787808f7d3c12fd9ad7983506c84406f70ec6024a53cc2f030f1f21a8e88972d8077b4283217513772313828938c48a115057fb0b86140d26b0f7e724d3b8c232997eb7eb471d0b5f79b0e6f0c9cbf6cc524cde1524c276e842b209d60adc2b1c0df4cdcd71b3a211c62179d0115fe02bdac98a81725ea19f318f8a80e20bb277d498e9efc92bf41b0e838b2936802c8b9d38487757dd9390ffe666046484551344a29f902a4b53c146fdeb7847b7a2aa67a04f2284a4e6589f5f27588bf77f1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148959);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1484");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw93086");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-cmdinj-nRHKgfHX");
  script_xref(name:"IAVA", value:"2021-A-0188-S");

  script_name(english:"Cisco SD-WAN vManage Command Injection (cisco-sa-vman-cmdinj-nRHKgfHX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-cmdinj-nRHKgfHX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7dcde31");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw93086");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw93086");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.5.1' }
];

 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw93086',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
