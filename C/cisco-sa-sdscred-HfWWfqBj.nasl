#TRUSTED 5003319ae190891616e1bfd303e757a1bca3f6f1f8fe9a26531ec780832c04fb1f083c4a7d1503359cfe3c7dfe8a4aae0a69d4d33f6bd2e8e3aea789b7892d676bd266e456c5d8c6584908fb1eedb9b8fd4cc4b351115765a20c3f5dae3261d3fc61b577003535eec597e3b1d8c5d1ac736f9f12f3ca32f367a1e3d2760d73074cd1109a115fb630b02126329856db5a35708b8620c8aae2d492fc462cc4a583ac4b02de21fcd372501ddcf907713f162cef95f8bdfb7b50570bd41c268486316b783b81e1152a1e144fc000e7a19245bdea962cd0fbc83cbc0b53e7a918f4fe1129c82e0fdbbe36d84e5866cbf41c67c25cf54dc3d0e22c904adf9560eaf5c8eb1f748b4f3758a828f76ed01437d7b1e0238031bc7b0eb63cc70f37ba35adefcacd901c310663ce37e6016599a8ad61efc70c697e4db9fdb15fb8bcf6fe30d563d953acf2189aee760ab2213d2c7c233029e445d165ec2aaae1d285d4889e6516506079d9531769ffd3f3381d5b9b49d43239cab08e712af252c8ca2e878cff8a5bde41d771218472926399d200753d8ed832aea67a8c4cabf4902bfea3ba3fd8938328e3ae61d0a64a1e0ec98bd3aa38e6e1be6f78353f060fba2fce143da5aa4b5784ea68ff7f467008af033780943c56ea26feaea0d1f9176af794f86622c66f8b96bcb5c95783a0aa0ccce7fb14add7b72bbbfae9808fa0405b00e51bbe
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142033);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/30");

  script_cve_id("CVE-2020-3180");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi59720");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi85074");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdscred-HfWWfqBj");

  script_name(english:"Cisco SD-WAN Solution Software Static Credentials (cisco-sa-sdscred-HfWWfqBj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in Cisco SD-WAN Solution Software due to the device having an account with a default, static
password. An unauthenticated, local attacker can exploit this, by using the default credentials, to log in with root
privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdscred-HfWWfqBj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb819b95");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi59720 and CSCvi85074.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_solution");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

vuln_ranges = make_array();

if ('vmanage' >< tolower(product_info.model))
  vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '18.4.5'},
    {'min_ver' : '19.2', 'fix_ver' : '19.2.2'}
  ];
else
  vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '18.3.6'},
  ];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi59720, CSCvi85074',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
