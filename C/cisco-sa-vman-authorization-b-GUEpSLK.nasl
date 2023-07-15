#TRUSTED 6111c794c4b8f476b4fd1424004975073e68356b0f32a822115f432baee7715da11d45c273202106be7de6548a3ddf16a9b4e221f6b9efccca794cd81ffbc00c0725dfeb5212bd4afa4a8e8912dcd993142d80e7cdaac44674774f7a0c0434bad820c84f58d2be6bfff34159ca93423289232b22641ec6aab9367d9071778e6aa21a234c1c3d2ac3930245083a034f98d4b866c4f54a06034f9525e421aa7023218635b410d59988c677f24110bec8fa5c7b92c30a7e4c98add5c8c7d882f890f9e9709b648a60b8de8c5a6f37a501c2761ad4591ea35eb3175d956e1b1766299eff6dae7833adc94810848a68559ec1ff66a13b7fda5f27336db0f63fd3c5c68d4291cb1a8d2672051f7b47ee836f592719667bff3ca27e0118ba05e8e8248c632cb5c5ac6369770f861c6c2e60cbca37b2d4559a1ce00cbe4d51f7e572d3f57414fde424a1e43e4eb4598a693e60e748ac3289d54c59210a3ac62ac9df2200bca449be246b0a98ddf3e72731de25bd05277a7d6d184c372e3511a5dc028f5d66a9e90e66a38689cf7686a0a14f219b7c887c5603957e83adf426eb6f042763fbada0f7446eef62975e88b0c82a6620416e4a32d8f8b8a79b748e38bb3fc118358fda4b131486d819ef44d0372ceb7ad33196049bb8bd79c57e6e3318be432f441cb3a51a904eed12190069c9681f7b71a10c5674c31d7307f743688fc72644
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147622);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/18");

  script_cve_id("CVE-2021-1464");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28370");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-authorization-b-GUEpSLK");
  script_xref(name:"IAVA", value:"2021-A-0118");

  script_name(english:"Cisco SD-WAN vManage Authorization Bypass (cisco-sa-vman-authorization-b-GUEpSLK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage installed on the remote host is affected by a vulnerability as referenced in the
cisco-sa-vman-authorization-b-GUEpSLK advisory due to insufficient input validation for certain commands. An
authenticated, remote attacker can exploit this, by sending crafted requests to the affected commands, in order to
bypass authorization checking and gain restricted access to the configuration information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-authorization-b-GUEpSLK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?872f214a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28370");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28370");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1464");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    {'min_ver': '0.0', 'fix_ver': '19.2.3.0'},
    {'min_ver': '20.0','fix_ver': '20.1.2'},
    {'min_ver': '20.3','fix_ver': '20.3.1'},
    {'min_ver': '20.4','fix_ver': '20.4.1'}
];

vuln_versions = make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu28370',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting,
  vuln_versions:vuln_versions
);
