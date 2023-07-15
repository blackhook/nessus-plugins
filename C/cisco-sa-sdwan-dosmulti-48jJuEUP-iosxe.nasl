#TRUSTED 0bf3e953ca87914ec328f79d5bd711d2df00fd85b96689b71580167f933b5ac9ec071713687e1af9b0ead6fa0cee6e0e3e6d9484f8eaa8de1a9f29ca809bb8b347a7bff184f2d465c8b6d59cbb2da942e15faf553599221bbbc59b615257627658473935be4efdaf5f53ebb966a3b1d3878fc2dd7e843f2e43f80550d0bebd57dae839c5cda07d5dc5808a3f14e94ca8bfab6e4d05ceef1fa09485e99c0d0027f6d2f6901077a88c697279787182a5847f84bb441292203bbdd969a1665a58b8d1ad4f504dfcfa9154332135100cd0c0ab915b751c25028e8e672b132ed454a5e2feed093e749768a550cb313ec72159997c00fa5db0e15e3bbf505419215d17e121e228b166febd29ce78cb6ea5973ca6e808ab3f599ffa292ec88b66a0283a9a8e002dc9e0e5731a704deca82f2074e7187a3fb638ce1ce2f9529d9842756c46459bbc8c016db80df0eb7d7645350d2a6ed42863c71b25f095cbd046b2ae1ef6d693bfff09bc1339174aca141834daec392de161b44e9bafd7946527e86f51050fdf93f069104f721d049d486d23409540d6f0754d793bd2fec3f9a9ddb5972fc5b9c3d29e25237876babda2a8beaaceb2ef088e3fee92f9e5747212b31b6921c2cc837b3f33237778dcc36180fcf80268a08608e87f5c87478fa5dd9eea80a6d2e937ea54937b3987fa9bc1a65686af77c5a7e35f10c9b58ca73b6d933973
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145707);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2021-1274");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11523");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-dosmulti-48jJuEUP");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco IOS XE SD-WAN DoS (cisco-sa-sdwan-dosmulti-48jJuEUP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by a denial of service (DoS)
vulnerability in the UDP connection response due the presence of a null dereference in vDaemon. An unauthenticated,
remote attacker can exploit this, by sending crafted traffic to an affected device, to cause a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-dosmulti-48jJuEUP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05f6f0f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11523");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt11523.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1274");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe_sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

vuln_ranges = [{ 'min_ver' : '16.9', 'fix_ver' : '16.12.4' }];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt11523',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
