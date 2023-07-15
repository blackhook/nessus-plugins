#TRUSTED 93891a6e913b581cbd45134029ecfa6979123a7c1917e8bbc72ce18f9a0db2fb48ebfdcabe1a2218faf36f3379b273f248df9c2e87faaccf8b9bf31fd38150ab06be767c02d49bd4d51b565d1cd214934c6ce0e12284759db4e3bb5339985fd28ff064490519d4c36f962925f9ca084a65e84f90f7b457918e555753c26603422d24aa99f9b917fddd3d7614ef99c0e5eb809a71f91bf3cf74c49df889f6b936bbb212e648030da442060e27d595d22ff8d4b36a0f8eb9c0cb67303810a0de95d656ef093499eac6aa04154f6b1225af80c5c4564587ebc849061d7e6db5409cd03e150bed8b86c8ef19bdc491246d08dada0f95a4dc97755066920f177bd5a73a279349fc136b57ef9294aed4dae87add5f1bec4e42275e1d12e321633fe571e9ce55b7fada115234fccd54cf270c79deb287c3da6c15f5763b35153a0680910457ba7abbc5453decf0b2476edff971381ee183a35b12ab033fb5b2a1729d71be26e150bdf7d74f726e9f73df24cda73ee40929228b30523e388d5ccc63f6c9201312db9048d6eb227c12390f2b6ec55856a201c486fa4a254c1db73bde51536d37e1b846d2b919403e9046a20ef772d0127a52abe7ae4724164491bb83ee583e0f4ff0daf801e2edfb05d0a44f243b04e24891f0867164bb13586ab82ccb822d95cb36438a64889564023407719d9661160bd2ea2e99f67eee5f66af85cf79
#TRUST-RSA-SHA256 3efab0c205585fbe26cac8cab5dfc950a8740d4b855645f7e6b67c4c89ff0cfbbc29b16d8c5fb24cd23c197fab8a1fb422e10fef772dab257c42d63825289346d04b4529cc82dfc0d04f62c4b62aa7a84f3111ea06c201eafdaeae44e05dee1e621b49544b7589f70abae5da744a9a8793e2517228b93613256f43303f70be4f83ca39bc9a82f578fd0471c6a2f443d23fa73931b6028f2c5105eeeeceda8722704432a20abac2acf9fdfd151c664831a5bd7c4cb1e671180012103e6dbca08ba71c9df75ceb623325c3b3282e6d96a71e6beb7bfeb3da1a9107dd359fd556abc99b43d7281e0851d87602e744e41dcf2c63fdc43537e91d043b338f4f4a257727811e7d44529f64340828cf66cd524c84e777fa346591dd0971c1aac4156864b861580b33f37d64e8e3026c8c695c9371b062258f14b18b9cb8f8db5d220f883f431c29a2b5f0182837facea2289594bb5205f0382eee5a6ebbceb63124df8aaa854f139ce256b2633327fecbadd3c42ac79a6a9dfdb58665d2d2a44fe5d8eea02f6848422618f01d7377e74ef95a0984af767e7111ac04d9980535f0930dbc91c1b008315d26d690edefa3d04c75fea8b4592fa84aeccf3d1065a41397651a3cc819b0f6bc40f98b786c8cc5c686926100a0c15299f6901cf4b0dd45f66445f4a0dd3d237992177f199e9b89e5a93b6f1832f7070b4d11125a81f65eef47bf
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170159);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_cve_id("CVE-2023-20007");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc84443");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv-rcedos-7HjP74jD");
  script_xref(name:"IAVA", value:"2023-A-0033");

  script_name(english:"Cisco RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers RCE and DoS (cisco-sa-sb-rv-rcedos-7HjP74jD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router
Firmware is affected by a vulnerability in the web-based management interface.
An authenticated, remote attacker can exploit this, via crafted HTTP input, to
execute arbitrary code on an affected device or cause the device to reload,
resulting in a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more
information.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv-rcedos-7HjP74jD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef2f9b4f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc84443");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc84443");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20007");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv340_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv340w_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv345_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv345p_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340w");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv345");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv345p");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (product_info['model'] !~ "^RV34(0W?|5P?)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '1.0.03.29' }];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwc84443',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
