#TRUSTED 06fb1b82f2ddc9b530f2e935ddc6d1e6e1175fd5ac7f0f40a7dcdc47c2c8132849a538e603faff1a568f1cd2f7d4552db8bede1d6fe00ad97ed3e43069db9371118e5f42bd10514308a61ce3af37f162f708fb1ea89def5e94037731323555fdbc28750c0cce585dc5c4822fbd160ef23e4a648057dc1196c22da2e0469a41fd60116110d2a3374d5c5e0c1d6058b86be4732a3f9d91326bf94af2f462337439d9652a021c850fa8c361fd48e5941c34218933b2895e772ca60d8e5f2fb888f9a68d7c0eea647fff9a58e80227bff22927a4d02941e389f58a217a30ca6bcf2715103f40dce45189edbb8c4f4426045863873c6631174aa7fcfe6a1eb8002e505cb495ee27b52e194b7a7261e61f186b778e9dbbbad37fab5d23a94a95c259ebe510d153126b585fa5d5f9568f06b29b45129182f6a18d885a9337b00ad4e679dc46b03905b0f1e908bdff62b2fae1a6eea42d09339f0f5b00c2a5c15332b87536e3f8d60dc341c96c2a446ea274db25046b1a04335bd9400a732ee376104c20c1b2c1216429c3ad2a1ac917a156ff3a307ca38af2487b2b5bad70a3a21e616000cc33ee7a6a3151a6e9451d315741e13eb5c3a692667382195815f086d2b3e1e3a423b0642cff6ccc7d83b41b05240690c6e294a8e3a23d1ab761553c2be12db42d7dfb5fdc118902a43dd976303ebedd992ee361ad8e59d3dd73dc56491683
#TRUST-RSA-SHA256 add2df4f260687cb04479c07e0a9a6413d2644dca5fdd0dbb5b32bf39b382b0b4d00c1a997abc18a37541fbb0e492928cfeab47bb615d593a813d0aa6d2b0c68311949beb68cb5b71787106707bdd1bf76749fe6a2d73613e437cccdb15872aea80fc377451b34abaed9cb13f0958e042595991562e8452b1ed4039d755ee2d9c671baac4ad7d7669725f8e7768970cf15ccf38c120b88d0cde64712a42d5f8c74c1e13fec03bf1b0b63498214ac4182c3d0088b0412c6f355d87ac50e69630931723cd29630444e048b91fcb0be20c42874c774e43949b84fc7db5dfbf5fc706b3f1339f5e1806738ef435168e3a0783341f6c9736cfb75c9333a2f87957969dd08ba768c62b69abee3e282a1cda3f7ef0459bafdf0b11a035c64835e393b82cd5b166e9040dea9329afa56a792b9ee32752a7172e6dfb89b46e03f48382826a2e44d84ce8b25da1c816d4daf9f0080e016956b2276c58579034cc5613e4da2fcddce8376a99aa877fcd6a421dc5b30c8858264ebfb31606863d6babc537a50db4c443cb6c8d68dbcfabd524050ffcef2edd7076c5df6dadfe573a46f7c0f1c66081b93714b501fb1df198abb031a274fb1e0a39fe9216ba733b173ca9c668b5b192da7ae479a96084952ea69400e88f65c1bde1a53337bf47ff73793c20c65f3c450d802d5766f5d4a13e0bcf4e5116d7a3542486ef15ef25d09707fa8f010
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140213);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2020-3504");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr91760");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucs-cli-dos-GQUxCnTe");
  script_xref(name:"IAVA", value:"2020-A-0398-S");

  script_name(english:"Cisco UCS Manager Software Local Management CLI DoS (cisco-sa-ucs-cli-dos-GQUxCnTe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Computing System (Managed) is affected by a DoS vulnerability.
The vulnerability is due to improper handling of CLI command parameters. An attacker could exploit this vulnerability
by executing specific commands on the local-mgmt CLI on an affected device. A sustained attack may result in a restart
of internal UCS Manager processes and a temporary loss of access to the UCS Manager CLI and web UI.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucs-cli-dos-GQUxCnTe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fa2bae3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr91760");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr91760");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(664);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('cisco_func.inc');
include('http.inc');
include('install_func.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'cisco_ucs_manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
version = tolower(install['version']);

if(cisco_gen_ver_compare(a:version, b:'4.0') >= 0 &&
    cisco_gen_ver_compare(a:version, b:'4.0(4i)') < 0
  )
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : See vendor.' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);

