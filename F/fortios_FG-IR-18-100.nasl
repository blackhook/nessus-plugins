#TRUSTED 67ea324bfbd298e055b5e328940f78f0fd66bba9a057298b76681842c9676c20c91fa290eddc7bd480b0ca08c75b91103c1d2ea20189f523a0713d931a38d8af1e5b355c12f17d05dcc9d7f281ec226fb977aaaf2751196ff0feb5636a4a4ecc65c8324f8ceddcbd64ace7d27dd9f47ae0a1adba40cb4db2db2919cb4407593c2a263d4741902f9d600b5c78dedf6ee5660c2aa8e9d3a34a986205ffd9774eb6701277af45660b0bc919d8d4852ea98d3e0435c1380a6f0016bbb60d4f66c6513e5475ba347d0eca0cf140f9eac6de33cf061537f22bc50260c6948f532675f61645768bd75e69ae199591d8e7911b138b23beac3e5bfaf888d6f307a9451de20db4fa3aad1f03ea35662aaa58c78a12dbc7b802e5d9a64a06526cb4d4c863f14eba4c566fa97fb10871c29304d9e728b95d886682ffa40de03fef5fae6b78247e880f9a71ce0ad86b47eb12691295fada28a11f5bd7f2d647dbb1b62924bbe030fe157cbed1af173796eb465bf742350e3b60a7a7d69dec534c576a070b0e6be0f531bd7d9385b38fdf8d27978dceb76a69514b335fc1616e61ee9dbf6f412df7c1b27085071b3d349bc994797688b77f2fd05cb233ba982e69dc6f12bdaf8542d6cda4ed52543256d908a297d0389b1776311179d0eb2063a20ad370b34ca21c4f83ef687bebecbd62e54efa22866b696b42992495b9793fad3cfe996fd2a9
#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(131283);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2018-9195");

  script_name(english:"Fortinet FortiOS < 5.6.12 / 6.x < 6.0.8 Information Disclosure MitM (FG-IR-18-100)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.12 or 6.x prior to 6.0.8. It is, therefore, affected by 
an information disclosure man-in-the-middle vulnerability in the FortiGuard services communication protocol due to the 
use of a hardcoded cryptographic key. A remote attacker with knowledge of the hardcoded key can exploit this via the 
network to eavesdrop and modify information sent and received from FortiGuard servers.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-100");
  # https://sec-consult.com/en/blog/advisories/weak-encryption-cipher-and-hardcoded-cryptographic-keys-in-fortinet-products/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca502f28");
  #https://docs.fortinet.com/document/fortigate/6.0.8/fortios-release-notes/901852/fortiguard-protocol-and-port-number
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db9c0891");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.12, 6.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin", "ssh_get_info.nasl");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");
  script_exclude_keys("Host/windows_local_checks");

  exit(0);
}

include('hostlevel_funcs.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version': '0.0', 'fixed_version': '5.6.12' },
  {'min_version': '6.0', 'fixed_version': '6.0.8' }
];

report =
  '\n  One or both of the following FortiOS settings are not present in the config;\n'
  +'    - set protocol https\n'
  +'    - set port 8888\n'
  +'  Ensure Fortiguard protocol and port are set appropriately,\n'
  +'  as per vendor instructions at http://www.nessus.org/u?db9c0891\n'
  +'\n'
  +'  Tenable does not print the user entry here for security & privacy reasons.';


vuln_settings = [ # Not_equal flag below ensure it only triggers if it can't find any of these three.
  {config_command:'full-configuration system fortiguard', config_value:"port (?:8888|443|53)"},  # So if it's not port 8888, 443, or 53
  {config_command:'full-configuration system fortiguard', config_value:"protocol https"}         # Or it's not protocol https
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, report:report, vuln_settings:vuln_settings, regex: TRUE, all_required:TRUE, not_equal:TRUE, show_check:'config');