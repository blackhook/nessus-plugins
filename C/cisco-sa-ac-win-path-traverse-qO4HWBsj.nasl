#TRUSTED 89b52aef912d0bbf89dfefe681ea4f6a50dafbf8a05c247afdc5eb2fe7de578ddaa803ce0d33f82cb4b51deaa45847bbbd95eca4bcc0105a96794c536e3f70da682fd9baf853e3556a7adf558ffab12af44580772f9f10c695215d60390a98f5c52dd98f018466568606575a70b0e9b82bd7820a0076ad9a3186fd41251f291cfa89f594e63223e4416e25e826cd24155e2d1e4a071b5fcd1ff67c54292a471c7cb722aa51e01213bc8ab29c0d0ba929451953a324a76d6ef8357861f3a4e61583de280d6edbbc99124cc8e97849600fbc8d65dbe93828ded1886eb5b9ca87171e835a8e67d3dca6dbe336e139a04ddd4a2e467952c9bc70f68c15eea4633b8822a714393a8fce7f427f2bd9b703b58fd828c1e3a61ba32c8be795c3476ff25567f3ab66d929c693d04d4d4effa1e34cd6de6e919069fe488e1c2a0603f6e5a50eb943c4086c237123f392096a454bf7ea005b42a57bd4e1e9ef2e3e6612da3acc8878fcafa19bcb50c8fdb1e54c949be5b4acb9caaf78ca808ca88b542d92d8b00e92f8b4b490c2a3db130071d89396d6aad1341e8523eb8f45b8710bd43c970eecd6132a1a34d6be248fc732e04f8284c53ccf41c2ea7dce6ed16dd017b84ef3bb1de50792bbfc99c05174ebff0a10c99410854c58848bf2c5a0b8dd1efe75d91ba411b8a40debed6763867ea711788b6691e6e32919eddbd29d500e25dbde
#TRUST-RSA-SHA256 9becfab1aa758ad5535c6be368382b03c804a962981f5382a7aa5e9c25b55fc0cc05136aadda1ae259bb00b20856177b4b1d4056258377ecec434163b4b3ca51bfb3101dd2a79afc21b0a28587e75ea4cd406c1ebff25f5d769d3b63c10aeb34aeb1b26d573f9554957780d90e685651c82e6c0aa7bde84b985058955688f62b031db4c88db0c8f40d0981e0d292862122522dc41b49b2f88b5badc603937a4ca4ce5a6d93a00adab9f68aa5eb08ef108ba4828c3b40fa5d69a124eda1d81e82399ebc0cb1d875e5c2cf2c13e0c60cd617073d5bf3e57d31092dd7c6f07eb0ff6ece7610ebd8459efeeb4632dcb15cb347c45c064ec11625f19d9fccbcd47be10057aa8d6b6d1a951aa89919e2a23b3f07edec8fcc520e8f3f973899da195af402eaa175cd873ed5aa304259375c83f5ed5e4f5bd49f3df8763a6957fbe33f7599fdcb9410a4b25a55cbd80cb1719f9194ebe774b51a3b6e55424974aa86cc629c847e4284d62cc2106794e873eb893367a7ba53451fb90b30d8aeb0e247276f164713a4169ed354faaa5292d00c6eb6fc5c5faab2ef284f2a99b2c95b3a6f12b1d62589c6fb34040f17c894ecb6c592f98a9b1e9567902e911deadc54a9359fa51ed67b4d2c76b0a8f3c776c20bbda6335752f00c4faa54237cf905ca3c7d858dfb64fc8619acad479fe4a10730053886ecc6c6ece9b807a45ce75b77762cbf
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134164);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id("CVE-2020-3153");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs46327");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ac-win-path-traverse-qO4HWBsj");
  script_xref(name:"IAVA", value:"2020-A-0080-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/11/14");

  script_name(english:"Cisco AnyConnect Secure Mobility Client for Windows Uncontrolled Search Path Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the installer component of Cisco AnyConnect Secure Mobility Client for Windows could allow an
authenticated local attacker to copy user-supplied files to system level directories with system level privileges.
The vulnerability is due to the incorrect handling of directory paths. An attacker could exploit this vulnerability
by creating a malicious file and copying the file to a system directory. An exploit could allow the attacker to copy
malicious files to arbitrary locations with system level privileges. This could include DLL pre-loading, DLL hijacking,
and other related attacks. To exploit this vulnerability, the attacker needs valid credentials on the Windows system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ac-win-path-traverse-qO4HWBsj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4657eb24");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs46327");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs46327");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3153");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco AnyConnect Priv Esc through Path Traversal');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:TRUE);

constraints = [{ 'fixed_version' : '4.8.02042' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

