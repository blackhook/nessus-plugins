#TRUSTED 708ca76daf0b444eb9924f20a71382c60255b91743abb021e3ea364dd00ec77b1a8322add5a37985552d8845e6aef4d85fcd7b01437785f89f2de574a09489b04bc7778ea2040178c7ed2e1e592e9a0153c3010d111eb63b44a7017731c5032d195c4d7a1166188eb6d6f26f491085f3c4622718de6f621b6b3d53ed81d9b03bbef37766cdd9d330bf4bf957a79a11f3fc525d1815e923201a9f054b12950667a89b1f4ecd6040238d6ee9a84a0132f4496ca26cbad17de4540e0e8d4f4365b1ad8a3b6a8590e4cc58f6360495fbb3fa6c255f41940ecc509577843a52ab7057a2d7f5ad2d7ed08381f59f365da513eb7262be4fc194fccb4cb6275f6b64725ab956b34ddbb9f8c38b2633dec6bfbf385f6039d86c176df4becf262424a8eef17380fa25975a19115293dad1999871fec948f848ad83b6893588d48148d1c095fb082fd943c2956764d782ddaca7ca39d535ca056414522935996f768a5e576d2d4998229c8656cc7c8b6e084ab82c5f75a4243a31bc12fa6331d57bfb34a1905139df0205ebfed4a10fbff112cda6eb50b0b3346a01917b6e488b1478f321271a46ecf97364ee67e66af32dbd94dd8d1468d9b4eff17f02510579a4b436f6c1bd5773af06e0417fb5486d60694eb6964e138a641308e96c2b3c08655d50afa5b303dab2f71f247db18acad94ec4c8e2c0cd55e906393d339d53c426c8914a5a
#TRUST-RSA-SHA256 a120277f2db322d0c7a959ab5ea59504e846a37678fe2afa13a15543613583557f26d09ef5f26ed4075bfdb94eab55eb05028d70a44789180b050885fd23017fb70b68d72c4a659c197d9bb2b4e7708a386589dba8a21c622589254a8f35263f01566a60bf548cc9ccbb138370873d2ac8e27f9750b8d14d995183db66170c10b2981dc42e1d17bbe3e855ec212dca223eeaf578895b34abf3820c34bea17cf0747c7158c4d2da635642534eb59ec0b0694999b6d5e861f0fc10bdf9b334bf679002ca4b95462b09220f392314cbead39548eb87ad56448547d59aa091df07c1b3f77e0865bda44bb1f4b5a9e545a15bbd54bd104443dd6790f66ebe0f5e7d62d6e1c9d8a3c1496b0c7301d097b8f9dff1aeb2cf5defa330b16ab02e74d824957a3b50892346b2a933b85c3f9bd1182bc24dff7a3f5b8bf82813318773955835e16d52e3ea4339e071e8b0761f6174cbd3d5b9de8ee31754fe5176f5c90b89d8f6b80a89c7ce0049c22c9b2052a03e026c91ff822c55d3e3fc12f5bca39d037c48c0c152e20a7fdf2cbae9a2ee61704f75b5e766e6fbb9de8c17a9bd5b122ebcc2ef128cc6a0484b72148f06faed3219bba1accf18e0b8ab789baab5e3068d443f31193346a84d515fd1bc9de68be147cf79bd71c3138b86f2fc4ce269229d17e0bbd4641dd632135d412e4cfda93d5b940827cca7951a173b993bb15e19d439
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165534);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20775", "CVE-2022-20818");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa52793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb54198");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-priv-E6e8tEdF");
  script_xref(name:"IAVA", value:"2022-A-0391");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation Vulnerabilities (cisco-sa-sd-wan-priv-E6e8tEdF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by multiple vulnerabilities.

  - Multiple vulnerabilities in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker
    to gain elevated privileges. These vulnerabilities are due to improper access controls on commands within
    the application CLI. An attacker could exploit these vulnerabilities by running a malicious command on the
    application CLI. A successful exploit could allow the attacker to execute arbitrary commands as the root
    user. (CVE-2022-20775, CVE-2022-20818)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-priv-E6e8tEdF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f045512");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa52793");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb54198");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa52793, CSCwb54198");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20818");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(25, 282);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.3' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.2' },
  { 'min_ver' : '20.8', 'fix_ver' : '20.8.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwa52793, CSCwb54198',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
