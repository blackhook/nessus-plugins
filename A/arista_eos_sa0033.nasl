#TRUSTED 8742364b655698b3918006882183bfc006aee1f7b2eb43689a6bd18ac1cfc2a7ae7b91a65f0ee256cbc0f4c0a8a3f24333c13de8bd0b428b4ec63b5dbc5f95412af30b259e4620ef60238585dd3683d7e420b78a75deb027b97f646350cad49d091b30eff1e3d95b1cdb603d8f50b711284d397a9d854dd078bc64040073e8837c74bd32eda25d88eba4f663ed3ab39b5ce379c0b66df129dd449b3f781010c4d8c45dbaafc2c918efa03c39b97ce5a590ffc48f41537d545583b75270c685d90f2c253a2f8c0e3bd056a127ebae28748eb2ea4806771ed8192df05b22bfadd6ce856db5d1f0373c7c8f85f69c84f87922da95b92e8d0b443cc38d75a160760c66427c008ff08535ed93bc7e5640479e405dd98dea2a5e89a9d3cf376f1d87493c8e6bdada73a25c81f288542617bef36bb551fbe83a3fdf541e521d02763fcef6a60bdbfd2838fcee308f235ed5eee04ef736c4a1825b5758a3cfdd70eb12ec147a802ddb0c1a34e5572a5e6c7fd9d68572504c160e8f7353ec8e7fb9ef8351324a12f32643c8ce91b526cc7d1e542468f76ec930845d0e26de9125a21cc329f0a280d94eff1c0378b730c5be0ebf30d90962bfb2dbf9a3be3db00bf578863bee92f05ebceac449d87129dfff2e22ca67f756ae2cbc81f6f8c98a4767a8f92cff032a0172d7c2e58323d5ccb1c68b00fc165d3e771a9a857c26fb7c61d56a45
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133859);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-5254");

  script_name(english:"Arista Networks Rib agent DoS (SA0033)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service (DoS) vulnerability.
The switch's Rib agent may restart if a malicious BGP peer sends a malformed path attribute in an UPDATE message,
resulting in a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/4423-security-advisory-33
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fc27627");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.20.2F or later. Alternatively, apply the patch or recommended mitigation
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version");

  exit(0);
}


include('arista_eos_func.inc');

version = get_kb_item_or_exit('Host/Arista-EOS/Version');
ext='SecurityAdvisory0033Hotfix.rpm 1.0.0/eng';
sha='b6aaa4c30854078861f6c10a54823b003d2698cb9120c487b59b66ff09c9503085b06e6cee0796cfcd1952e5b3325bed1430b898f940a16d3635e1b3f2b7b49d';

if(eos_extension_installed(ext:ext, sha:sha))
  exit(0, 'The Arista device is not vulnerable, as a relevant hotfix has been installed.');

vmatrix = make_array();
vmatrix['F'] =    make_list('4.20.1');
vmatrix['fix'] = 'Apply one of the vendor supplied patches or mitigations or upgrade to EOS 4.20.2F or later';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
