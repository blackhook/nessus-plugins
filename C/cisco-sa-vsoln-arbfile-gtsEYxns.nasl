#TRUSTED 3e69de2f167a9a8991469417d680e915f0c7df3b239353ff1f29c1032a6fb19634852b191e0c116eba08b6b31e725b63ad376b018b3ab2f8c96f22e9c1817737d43e96537b71202d38f79a3ccc3fd6e0fa1671d105e013a6fabf1d6f97b3471a98fb8df919ae68d9cbca687ed22d7ecf5d93fc9c1c75b269dc591ead5b9c9798fbfa8bd45db93732f1d4bf949915cf3b7fbea764d733c7b338d0fee2b5db7625f0d942714f68866d35f72b6846233315ddcd1075f9b595423b5d36a11e5c2cf8763f7a655ecb13500cac601e2c9a386feda5c39302dc55329635dbadc1fd87fc5cd03864c5dd364e68bf4b943d9eca53a8c63a25ff5813af3edd933b02984321c6e6498963a71180ed8d4e101ea0708ce5d37e76ee4407dd800479baff8a9ed894b64a20b3db346096048fe65c69367c2979a17a14c2b37b0ffa172ce730fb824bd0af4b5bf5e1ab84d598e796f29879b5050e9ae2e8b9a050c1e6ed839ab42733991ec4477c6eaf5571d57edf8ab93f41dda138e8047a3d14a3d7e883fcb569e3dccce62f180493d24d24feaf69293a2ffe9cd323ac988461f1cd7ae2636ef381a79d8dbf281935fb456a2b6723ee0cb3eed178310cce6a9604ca945b0082254a5afab76b8e0379b4d06cbfd0646cfe8b636de628f383d2002c298ff4ba3afd88019054978467f14362c3be5f16900f0837b51f850725a398d6e48a1363e8ef
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142661);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/12");

  script_cve_id("CVE-2020-26071");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv09807");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vsoln-arbfile-gtsEYxns");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN Software Arbitrary File Creation (cisco-sa-vsoln-arbfile-gtsEYxns)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Software is affected by an arbitrary file creation vulnerability
due to insufficient input validation for specific commands. An authenticated, local attacker can exploit this, by
including crafted arguments to the vulnerable commands, to create or overwrite files, which could result in a denial of
service condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vsoln-arbfile-gtsEYxns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba488803");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv09807");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv09807.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26071");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

vuln_ranges = [
  { 'min_ver':'20.1.0', 'fix_ver':'20.1.2' },
  { 'min_ver':'20.3.0', 'fix_ver':'20.3.1' }
];

# 20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv09807',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
