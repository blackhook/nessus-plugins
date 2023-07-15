#TRUSTED 50f3716b7797e2f71c23400a58018c4622d91404280678217e2d0db685d2580d054813a4bbf894057630394f30663305ae51f7bc90dd544f3ea1110b34f3f2a135274b34814c39f6f7773785b63f72e474a6558898fc86cb7b76e52592ffc76d32a84ce55290fa1f29c3d320b6b09152d83bb678f6a836fa123186040e12c1d769faec8e537d589432cd611c4dc41e83e55032dfa103a00ea8bd70b2a39977b3b094d8a6bb215feb20925b47cb1d87c002003eab503a3a016ffbfcbce449e223beed55687db04727e6232f7568ce73d84811cf2fa2dc1483fa01e79627d6c65311a9998afdb53b80140a14549cb73c84dc96273a8db84135f044f3d354628a192fc0be80ed0d038aa752e6ee76a6e2134744d2e303db79c7f4e867e51a19e03c55b37ad56b846a511fd6d32a4a576eedc8c3d48b7fd2b475c8666844d9c3c79d2f71528dcfece2f581ce8b21175212f54661012e22f5d53097d49d48ea466ce2a0d562f1525deaf4cdf5ca17c07de013c0dc5410da722680e4b2821b4e1aeda42687031b00937dadcf58804bded71f0872cd85695cbe0a1f67be9b9f958633036b4bc931cc353eb0ea12c6d1f69dc6be348d06172178c4e0a5f8b208514b9592d3c37053a9b7789f6c2e42a849a8b46c89aa90c9480a078cd9f18b29f88712d9cb72a119235b6263f7347df089e9d8fb0f768e347875af7c7f09e878c0e40115
#TRUST-RSA-SHA256 320aeca33bea8c0e5c11f549ebea69824a3625232d92bac13476b70d25ae1545f28273c6a99e6d4596b7a3c6efd5e87dabb3e953d0135813c746705a45787dcb731078f301e98072d6f758e0abc2fee936192a07347d0b29c2cec16264ef48dfbfc52c40fba91bfe96e237edfb1eef502690b80610ca9c77a9dee884c1aae130b5419d8412a13430be1b77838fb93f2cf81fc21863c623d9478c6c0c4716f1e4d412c90aa3b87082f03f5851e774724090cbea23ddac0eb88788e0188439603f2baa53d05209b4876944877c56cea754b7ec3b8def9d17283064505d6ae563c301952ee1ae92a52c14881424afc5d91013a409a16cc835150c7f54212196bb50a602f191cd69f74716cd85d4d52993f7032019b5902e1e376ea2df74573aafce87d9a60d4bfde76ba1f6c265ca3bdc92bdf9e6aa7ec0e939ba29481a5be15467e7c6d3d163505ba4494d4508149c6a4fc7a7189c8823912f103f556e7bcc8eac663e2ce073e4c37c785731b173ed29d81ee5f524ca7af3c0952a9cd43aa562cdd82f54c921bd8b0116975acc7192ef1f0e872d6c394bebacb8cc26575dcb32a324e186a805a2d0c48c34edb4defd19d2fd44b5c7a6261147c04a23650e2b142032f1885cc3fd42114b8d01ed3930e5c98792bbea5f1d27dfc370b29f9f48db4d122a3d9f15e061094058374257321f0555fd5e52bacf566969d2198b7824cb89
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149298);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1256");
  script_xref(name:"IAVA", value:"2021-A-0205-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu29184");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-file-overwrite-XknRjGdB");

  script_name(english:"Cisco Firepower Threat Defense Software Command File Overwrite (cisco-sa-ftd-file-overwrite-XknRjGdB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Firepower Threat Defense (FTD) Software running on the remote
device is affected by a file overwrite vulnerability due to insufficient validation of user input. An authenticated,
local attacker can exploit this, by logging in and issuing a crafted command, in order to  overwrite files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-file-overwrite-XknRjGdB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90e2b837");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu29184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu29184");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver' : '6.4.0', 'fix_ver' : '6.4.0.12'},
  {'min_ver' : '6.5.0', 'fix_ver' : '6.6.3'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu29184',
  'disable_caveat', TRUE,
  'fix'      , '6.4.0.12 / 6.6.4 / 6.7.0'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
