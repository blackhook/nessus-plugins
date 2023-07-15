#TRUSTED 8c582da9fce4573c5b3b13ea6dc8d7378c16089549293bdc9c46e0b84b3a6ab6d841e7048d6fa1660c0ce485b1c152461ca0cb3a8deaaa0663c42342b4ca0a3acb50fd37e73547707a2e0171ebfd7d57b156a0d685fb2cc75b6f9a78a8f179f60e669b7aadb23efe252db23283159244b29406fcdbc2b92eb625f7b873024e873ce87c25e5946095b140aecde5a23633c8cc530f9f0c61e51ab54852a03b168047cd1e067be8964c796478e73f494f997e570626e4f5daa28b5073f287380bf5add8cc3a846b6e2b016e3f1be52417ea102932779b7597ae6fedecdaa9ed760eccdea9aafcbc195ed287f723cc8fb46ddc91e0a2d99601d787b1464806b8b3f101985f1a760fab618ec4f7cd217924df31b2f31510dd591552378b68e5f4aa12df2d2ec68315d2667e8c702bcd748a89351d812bb3bfae60ab29db4f3a16a61395deffce26fe99249b476de017a9446317bd86aa18d034d30abceb3ea038f3f005b09376561f296303f57935f88373337d54fec6059d33d4d28ddf0c1d9f2a55ed479e359b04a39c4c125c7ee8718ef3a00e5a3daa1a3f03270a9ce5d435d376ab514f27cc680c2c14983d854172fad4bff030c1750f067714c4ffb00f1cc14df21aa55599caef8ecef46a1c4589cf1d2e181317ee1f17b47109055c85bfd277043446e27a45c095f719a8233d4dab3a3fbebdcdc11f71676c87b8ac0ebe0159
#TRUST-RSA-SHA256 33eacafadb2a0209fac7538a56cf9a44148012b5bc25f156ef8607e4825cd46a44b23f01c2f8f61bcd4b4cb18e62544fec75d1009a00af7fcb727253a2bc555f1ec8c390b475603d4bb322bd5cdb80a0d2ebbebcfd797a6951fc73cafd78fb34d98aa13460fa6794a3e6d78ee0ba7ad943387489c61606d639ad47e86113553392039f0474bb21b0adaa2bec85343104c2ed9481566d8b6f59c16864766add5b3af7447ba2d75ae32ed9ae2e9cb5653389fad996b818afddd2c486d297f86ec62498b8808c43ad3460d77d064cca45e77be7e1e07bde1fb24980e1af938fafb343229fc9856a7f3a3f3beddd33f304209b5ac4b9574d3226d284ea249ccaa16cf9a129a58c7a5d0ffe3082dd5ae147db37285b981989df1983b0cb2097e6627a43f6a73e925335abbbd3ebedb2f8828b632edebd5305290771fe718848fea43b7aed8ea8db1287be3ae99972ae41544254820243e5f740f88b87b64cae4f9ea6122b9eb0d6886a1f50eca59653d04eb6e6ebb05d20ed2f1e5d0fa2a27887e14ff2a3e0a22a75ac56244729b0515cfa8ed691ac222e0abb6dfd09b70328202637cac20bbbcf13346e75816a1abfde79e20f6fdd7f2d2f44746c3ba555cdca00c26276ac791006d0e31046b5fbae9c3ecbdcd3f8c9ff30748eea92d4e46fd3d5de4b1caf55f930b3e5d5f88335a504dd7c7f67fd2e26a7d40713cc0888024ecf79
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148306);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-27124");
  script_xref(name:"IAVA", value:"2020-A-0488-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt64822");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ssl-dos-7uZWwSEy");

  script_name(english:"Cisco Adaptive Security Appliance Software SSL/TLS DoS (cisco-sa-asa-ssl-dos-7uZWwSEy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco Adaptive Security Appliance due to improper error handling on
established SSL/TLS connections. An unauthenticated, remote attacker can exploit this issue, by establishing an SSL/TLS
connection with the affected device and then sending a malicious SSL/TLS message within that connection, to cause the
device to reload.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssl-dos-7uZWwSEy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ad5aa6e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt64822");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt64822");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27124");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(457);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

version_list = make_list('9.13.1.12', '9.13.1.13', '9.14.1.10');

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['asa_ssl_tls'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt64822',
  'cmds'     , make_list('show asp table socket')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);