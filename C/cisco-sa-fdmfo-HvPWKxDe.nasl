#TRUSTED 86192f7cc06b03ee63660eeb5fabec1d6064c756e6818d83c7a528f359ba7649082c4a4dc24a198fcb0cb1c4d0daacbc43c968348f35ceea50de7359a5841a8fca104fcb026396c2b4cce258fa4b82e0fa8814b6b5a2d32d3f7c67a56d126ce06bb3a96ff6289b39cb014bbefddada91dec29648588ddb124cb7574e33739484f9733e9e2615bd8b60f40c677c0efce4b78c9d216e7a3fd21d6bd17626147ac2f2d8e42afde74d09e1c0381e66f5236278aff3da9b7b28355e25224c7da2b6fbc0bbc6ea3e533243adf5534cc989740ec1095752c7323a83b6a61dde9b60098c036c26ad34dd9d2c81031f85fe958153fc0dc84340f06914ec1ae17622a990124ee5dec4996a7827f8d37ff88a790e89a294c71912eb8c15f438c2481f14abbbda5d93a7f6f4377107dc0d08ccf41d67afd5e64ce5461b26f50d0fb1dc77bb56ebcc5a8dde9ea2f030b5b00e666517c1fd557ac3abf609804867aab777f5e6c6829387717ed79db6966cc12163d45ec3b9eb8bb6b8e540143297569778e4f1eedc1d27902c1aa12ea6ec69df1dba8d458d7b0f98d4d579c419b56a2d2c3e869c202d688b3e8baa9e3476157e35319613657520c7f688db979816c3e12e5c05d9bb4f17a767699858b27a2dc2e3fac1ac7ac9956a02ad6931a749d5c1c5e0a7802f883013c1c24fd9bea7a16a1923f4d3f7425229299c86f90f0b4398d0252a3c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138446);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/13");

  script_cve_id("CVE-2020-3309");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg48913");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fdmfo-HvPWKxDe");

  script_name(english:"Cisco Firepower Device Manager On-Box Software Arbitrary File Overwrite (cisco-sa-fdmfo-HvPWKxDe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Device Manager (FDM) On-Box software is affected by an
arbitrary file overwrite vulnerability due to improper input validation. An authenticated, remote attacker can exploit
this by uploading a malicious file to an affected device in order to overwrite arbitrary files on the underlying
operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fdmfo-HvPWKxDe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4adfe580");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg48913");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg48913");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_device_manager_on-box");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_device_manager_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "installed_sw/Cisco Firepower Device Manager Web Interface");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');
include('http.inc');

get_kb_item_or_exit("Host/local_checks_enabled");
port = get_http_port(default:443, embedded:TRUE);
product_info = cisco::get_product_info(name:'Cisco Firepower Device Manager Web Interface', port:port);

# Strip part after -, not needed here
if ('-' >< product_info.version)
{
  product_info.version = split(product_info.version, sep:'-', keep:FALSE);
  product_info.version = product_info.version[0];
}

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.2.3'},
];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg48900',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
