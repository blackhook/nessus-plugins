#TRUSTED 5b35f6f7233fdcd78e5269a8794ed71dff41301323ba7e639670ca0bcea16c4e604e19f47f599a33df9c128a63015d4420c046b276b3450f9a8d778854293c6145768c2240b89b560f9bc62a3be1a46b370678f8850a6ea47cb3f29e54dcb17d08371fd41d9a45cc3935ae584e38a14f107ec897cda00a2ae67f1e245dddfbe11bde3b3ac269501e4c60687a6bbf8fdedbf81a79920c9f188ddffa3a9ecb640a378b30d0b408835c6375fa879e82582cf53ff4059418505c82b2278d2b4868d3de80f996fdb654d8554bfd94b39651ae782414112d195a48e8189e73635541b7565759fa420d20f6764649a1bba395d11011311f5ad37f189dfcbba92b4a1bfc1c6b7871fb4211890991a66d5c9aa77939d3710c5b9599363805abb081a0ee8833ebb481a6934846ad7959f8a593924a4787c1094fe5bedb21f6f2727bf98cdf70ca899d8d30a0abc2770678febff09e3d5856dcba51e2324d4a757f97a086039f517d5fbaba175a94bd65673e7a4065412933eabeeae1bf9b831feb18cd935baf884c858b2e524bc181e2f1deff87dd40f16802aa45668970e8f0c65dd15c2b52236fa93d07bc51859e63fd3ea55a0cfe18b30c7895fe2a2ba689fc2b5c8afa0528aff9aad48149c323ede0daa41548a13b8bc24bac9bc1af56ae2a8ab2ea490faf0fac8a8b371ef69aa0de8e8648c90cb3e392b3c7034fa12a7308ba5793ee
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141437);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu30597");
  script_xref(name:"CISCO-SA", value:"cisco-sa-le-drTOB625");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE & Cisco IOS XE SDWAN Ethernet Frame DoS (cisco-sa-le-drTOB625)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE or Cisco IOS XE SDWAN is affected by a denial of service (DoS) 
vulnerability in its networking component due to a failure to handle malformed ethernet frames. An unauthenticated, 
adjacent attacker can exploit this issue, by sending specially crafted ethernet frames to an affected device, to force 
a reload of the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-le-drTOB625
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?218a376f");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu30597");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu30597");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = toupper(product_info['model']);
if(!pgrep(pattern:"C9800-C?L|ISR((10|43)[0-9]{2}|4221|V)|IR11[0-9]{2}|CSR10[0-9]{2}V|ESR63[0-9]{2}|VG400", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list = make_list(
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.1w',
  '16.12.2',
  '16.12.1y',
  '16.12.2a',
  '16.12.3',
  '16.12.2s',
  '16.12.1x',
  '16.12.1t',
  '16.12.2t',
  '16.12.3s',
  '16.12.1z',
  '16.12.3a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.2',
  '17.1.1t',
  '17.2.1',
  '17.2.1r',
  '17.2.1a',
  '17.2.1t',
  '17.2.1v'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu30597',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
