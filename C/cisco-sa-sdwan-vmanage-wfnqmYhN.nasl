#TRUSTED 8fd7c70f65ac3629a6b644ef44e545e2a8fec4d8c4860736b824c4e3d87854f5ae29ab61e21cab086a8e90238c415f572fd051122f32a3a6769c303cb8d91391f203ea374dac19de50ec9077ba0d4559b05cd65de453729f9e444f0190570d26f90d70a0e238b691d98f4e8a9bd2b03f7d08607ae0960c27d230250343e5502c9e91e8a5ae2533b2ce9e745434940457b1de7dd63ed726ebde586ca1987729d843c11619b60fdea3bdab583baf873bf23df33a89f97636bae2da9068e6033a2a2d47a461afeefe01a4487dcc77dd152b238a051da72544075d61945c12bf0756c67cc1969223f00f124dd67c3400dc9ed6310a1591db254e3d0b554fd3592c4e3b12f113eb5167f66cb7a11e1c60df5efcff24448cea3dc6cbcc47c63eb2c4441cf4fb5240a70f240a2db8e9b75fff36c6b893de48fcf6978567e27f6f1eb99cab8bda060d983a4bc5440c24ed2e253db2ce8f86c8f2ce6bd47a4005885902815ec53008bccc88041ae11fe9a2a5353d083eccebda28c86d526ac9af9037df9766308971f4d0cf7f8dce3aac69da8f205b04301c555828b4918f4e8207545c82df6ac7015e149638f6a03bc9c3754afba387a0e7ca2f2a3af03ae3d0005d5ded72b716f6e0b3342bc91f6026243ee87acb286172d1cd6f871d18a141186ab8433aae72efe29c7dce1c07f280a9038aabe3eb62b635f81b2224fc11841212f8d7
#TRUST-RSA-SHA256 56fef0fa5ff6fc1f267d4feb9a8e61c2f4d3375c85baa11d2e520fbc9780d710aec8a9f2cdd93c5dadcca6d8229b0b2991e427c316350fd8781f32171cbdeb33be056d42b93f4fa1a466c23104857ff3a03ab57ea8cf6bd1be255520217057134f6cf614ef3a304f6fe897a519c4300961d7ba3f18ecebc361bb15692ffac1feb2a72a4b72f5effc88ca97430a3ea451de4c02d0c3f2eb79f3660ad3f8bbe147204f39a057c1903aaf419b640da991e5f9d93b701bd3aecd3e5a5b1af9cdaf3603b711784d883d819d624392ec0b56d191a3ca3ae30be58aaddb17577458095c363d8b06ba67a919d1f181790437f93dc370c2d35780934438080e325f830169a655092de391669a8ea1e2f79f790125c6f286beddce95654fa1947355720cea5836a388c79cdefdf4a24a69cfb46d5e40d75c9196cbc7d747b206f1875340de944da182f8e02cf2d2dcb800fddf6ba0f3b661834fd50bc03c82a014c587e65ac503e8bb23a2dd0bda2ec080b262969c6214d3818b6a997b9ae1a2b288d9cbb7a98c90cbc977e10eafd1c4add33ec4a387f272bfe4f4b6d7f845abf8bb8485902a94e3b3d9e19fc22dda5af2c4763ee0322034b096070526a01ba830765c9b5531f22f53f97a5e41ed821d68f6e5549424209bdf7878a31af3bbccd7683776b97901532deac2f5e73157a90aa2c697f50ee66864b33d45e431349c6dec957811
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174456);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_cve_id("CVE-2023-20098");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd42486");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vmanage-wfnqmYhN");

  script_name(english:"Cisco SD-WAN vManage Software Arbitrary File Deletion (cisco-sa-sdwan-vmanage-wfnqmYhN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SDWAN vManage Software could allow an authenticated, local attacker to
    delete arbitrary files. This vulnerability is due to improper filtering of directory traversal character
    sequences within system commands. An attacker with administrative privileges could exploit this
    vulnerability by running a system command containing directory traversal character sequences to target an
    arbitrary file. A successful exploit could allow the attacker to delete arbitrary files from the system,
    including files owned by root. (CVE-2023-20098)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vmanage-wfnqmYhN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4b50864");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd42486");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd42486");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20098");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '20.10', 'fix_ver' : '20.11.1' },
  { 'min_ver' : '20.9', 'fix_ver' : '20.9.3' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwd42486',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
