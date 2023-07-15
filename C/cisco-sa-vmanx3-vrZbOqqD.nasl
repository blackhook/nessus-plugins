#TRUSTED 349b144bd2b6e54b866366479d02606f037bf8af1c4d215ba5805997f45b38f9c9ed7512ebbca48db973b9d7aa8da0c875a60e46610928e20e3a928de7fe2faa43f3c0e770c9765aae28044cb11b206a9c469013a215814c562fa67f0b666901c5ff894facd2282db80bcad00f7ac9f76343162edd65ef7432d2aaed1633697a7ad6381ae7c4379c00b25c0995d483c084aec821678a1f3e3aef25864f8a8c78eb45c149e78d520f67afca78c4d4606557ded3d0ddac398629d91989b80c5e9352d00d8a165c68a49b8975e5932cc8835167f9db1ef1ef521d56b8bf1f59b0be5284cc49b28a063dc48690c2a51447973fe1f320a0bc7711d2e0ad131b0e95a43e62a0624f648c564674f4b5c3e46d97e36baa579ea78a8b1a66a7f621d2c26212ba52e09a44e7b90a26ed3fb2506f1b9ea6dc8b36fd7e7d97fd2809bdc16c23e84ebbc81db06e66e08181d51e57022927152a38736c28dca910efb5a529a9aa6011c7e79a320bdbca2b976ab9fd34df01d2edccf657743f05318e8a645195bfb8a6458af978a6439a89938c1549792653767c4bed20807cf05cdab4d7664faac5de6522e379428b6d45b8a539e115602fb7d86ff263e8a6d1c2cbd429396aac52fa46f4fa06e8f63d42da31021d4daf0c531f9c069b0fa5ad75597623b36aed7a4260ee3b0c4869a3a6b851cf62a4ea736d1e6e11c5c9c50c58769e2fee364b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143232);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2020-26066");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv09746");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanx3-vrZbOqqD");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software XXE (cisco-sa-vmanx3-vrZbOqqD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an XML external entity (XXE) 
vulnerability due to an incorrectly configured XML parser accepting XML external entities from an untrusted source. 
An authenticated, remote attacker can exploit this, via specially crafted XML data, to gain read and write access to
information stored on an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanx3-vrZbOqqD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aaf9951b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv09746");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv09746");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26066");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
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

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

# 0 - 20.1.1.1 covered by ranges below.
# Versions between 20.1.1.1 and fix covered by vuln_versions here.
# See https://software.cisco.com/download/home/286320995/type/286321039/release/20.3.2 for more details.
vuln_versions = make_list(
  '20.3.1',
  '20.1.12',
  '20.1.2',
  '20.1.1.1'
);

vuln_ranges = [{'min_ver': '0.0', 'fix_ver': '20.1.1.1'}];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv09746',
  'fix'      , '20.3.2',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions,
  vuln_ranges:vuln_ranges
);
