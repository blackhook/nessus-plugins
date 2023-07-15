#TRUSTED 98388847d3adbc12d94edd19bb741c5e15315c84301d251ebfb20057234776d688df15fcae0886e786896791a98cbb6a241edb396de169a5cb312ec3c7bc2764e9bd299819f58269ef1664645370e24d01587ec50f6c9c8a211fd09b0a94d224e5d2802a6db70fe097f52f3b5a4b00fc1278c208ed2020251c69a3ed55f5f581c2dfea7ac89c185339034d2d4635ed01406234dee05a9e6dae9244df5aa6fb6d634dcbd9c026a5889b4caca6ec5ad3b17c0df8db4957afed11a047356477afc543b740731de4511c49b2efb97e7b75faf40518930f97cd2ad54f7f3276df8da95be0ee8b005a7c342299ca2ae072c7a5c27427a1eb8a1ff01a57c7ca6fe48a7a4b7a93fd37fe8230fe8f29d83891ba9de5c8e2675d77a24040da9d6cae868e6bb4b75b14316e54255255b3d8f53f372dd5f00a5147e085361d617057989ff571ebc393e6236e14a186654815122cf62670786ef1186485777d1f83d955434d136f95f8ba4c783b4a31bfad45121e647778b22650ce5f9003ac276e4e1d902d095b18b8b9356687f453d91d475797a33fbe30a4e37759beb696c615d6b143e4e7c2bee8289f58866793a81a38e7bc937a55d8d7ce272e94e5274704198a02c2f31614ecf3fd0838f1644b14aaae26c458f66c6468bd8596cdd189f12181a665f8dd5e3279695afb73b6403b5004be5abbbedb060d5e792a4f932174ad91acc2ef
#TRUST-RSA-SHA256 12c6140583663381a2e09dd77f9ce74b869f3d9ee82fe46d13c9f1d738163c3b6419cb175459d95c0219139250b4a464baa445a3ca0e887a88db7a2788b022545213de5ff039a84fe5a57017c5b3a0358aec526f12ff08f5b73107e92eb43b7e96aed386d5538b44a8597a7b6fc5d251345b1cf0548196e5a062782ab03909b9003a0f2ac117e69d2d8bc33aa0b0eea64eb6ff8e0f55fabf321ead97f368f49493051eea2d35d78d8252d6613a227d7ff62e7c4e5244b0bdff81ebe41798252f2c76008406aa9535cdcac2f34ff51a61037ac5f773b2f2286d8daca692719ecb3c445848b5f18095dafc0a93ecd87fc86575f03747de654710523e448e2bf815d8171e074f1564578bd34e7317901abbe8a4beab31f7ada59976928138cc39067049c8c04f6708b0feea11e00e15035a9e335c72802f909c3ef9ab1bb849c8f7dc526ab2eb0b02cf9d1f80dfe7e8af917d2e84e2ce19c798898cec548e4c6ace9f7d9be18a1a13458b19de1d8d84d00c47a0cb22e2ed51b84cca16cc95299e820eca933c28fe313378eafb027015c583e5c43d4523a4e25d3a9ef0a8f8b662063350be7977d7304a5c08bde9da80a76342e64ecd8b43eb0242c49f1724d7918c42a4ca25091935aec02eb48d548892ac2f9b7c7202219cdcd5ad8de8d2434ead05ea96cbcb9900874c9a32a1b737d31de1c10fd87283ac024ab25d800600db67
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161699);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/14");

  script_cve_id("CVE-2020-3433");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu14943");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-dll-F26WwJW");
  script_xref(name:"IAVA", value:"2020-A-0351-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/11/14");

  script_name(english:"Cisco AnyConnect Secure Mobility Client for Windows DLL Hijacking");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco AnyConnect Secure Mobility Client is affected a vulnerability in the 
interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for Windows could allow an 
authenticated, local attacker to perform a DLL hijacking attack. To exploit this vulnerability, the attacker would need 
to have valid credentials on the Windows system. (CVE-2020-3433)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-dll-F26WwJW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88c8089d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu14943");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu14943");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3433");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco AnyConnect Privilege Escalations (CVE-2020-3153 and CVE-2020-3433)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:TRUE);

// earlier than 4.9.00086 is vuln
constraints = [
  { 'fixed_version' : '4.9.00086', 'fixed_display' : 'Please see advisory' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);