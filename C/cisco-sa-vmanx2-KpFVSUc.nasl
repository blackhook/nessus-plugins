#TRUSTED 68540fd7bdeff062196aa932ac72e13de846a077820d59ab33c3d42644728be66202f86616ce2cb52a84bf9d09cde8bac647c8dca4de6e5238759631273f12ecb8773d10fc5f59cf325084e609a1139881a393f18511211b97ae89a72026fa1cc7ae3f0195af92a9dc77d4108fd52de6782246fed19e7110f74f07d0c6f1ca0b4882aaecaf862557e1bf279581240a5b88e607431799b90bea7365862ea2ff0feb495fc5e72b656ecd37875196d937b57a893995c02ee8059ca0c6bda367227c4add6602f8a069cadff01ee55b6bfa85011b580b39bb035fc24e1da3520026762694262cef8c6ec400236d2f9f2a3b96acfe5ca80dda75fca8355be17dbc919ad24462e018ad594e96c382a5e0776e2e5195e82112a6ac73f05390fd79a8bd46d5c4c9b30c058c2d30d8c5fc1ec1e2c6f7c963fa5fc98728afa3f30e383b44f23ae3a5d9807c3ea5bdf40afc64aff73e86284aeeb852ebf35d8d7ee93d8ebc09675b93e5b19d831cd616f3d1907158352606b916b7f2873d09eb644e764be13bee259331031191f503c254b72e97781ef425cbb4d85c123402bd390d3fd706b1315c8f3154d2626d663c91787de05313b999dd36f22d0f425171f274a651bf8605fa45f96df99ebfc4325c250bc8b48b8f9460856f23f6d7f08514cfa7acd3cbdd10ada9347d34c757ef88292b1c6837c3cb038ed5a2c6ab6df4a3c2ea768401
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145556);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2020-26064");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv02305");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanx2-KpFVSUc");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software XXE (cisco-sa-vmanx2-KpFVSUc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-vmanx2-KpFVSUc)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an XML external entity (XXE) vulnerability
due to an issue parsing certain XML files. An authenticated, remote attacker can exploit this, by persuading a user to
import a crafted XML file with malicious entries, to gain read and write access to information stored on an affected
system.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanx2-KpFVSUc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4f1f4f2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv02305");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv02305");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'20.1.2' }
];

#20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv02305',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
