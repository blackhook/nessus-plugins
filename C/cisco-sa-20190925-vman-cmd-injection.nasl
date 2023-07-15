#TRUSTED 953f8875b635ea56036eb1fb604c0718039b0434fec883c02bd523adaedad39820e9675144c69f4f8be8228e941e792a99af106203a0cc49d476870ed5098efe1b8b19d2783f612073acc64b427424e8aa7c85c841423264482ef674286ee55b4f7ac5ff324dcc50984cf8ed1c5782f49249f5422208deb2c1ad4b3f13b23f26ea37f15f16bacba6b91d8f33468e79f2c9032d228987ad659d994e74e6689e31715b1ee3062191cb7bd9e46507e6f87f59dd852e33de892fadf28e052439cf148cacbec2a4373e429299d8107b490c46aac74d1c4b65d2b717cfa5dd0aa984c72a3946c8cf3b90fb3ea167af3edbca07032a4fee0fb30465839bfa396607b6c2f92542cdc3ea52855b129b176fd9ad1e3e599ed15c6cf7c4d9fd7a4390257c9faba24a25a776c3a4a2c0bac4811f40bceb05c9038badcb3022bcf9bbaae84a4153220024b4341bcc6c3079b65d0c71adc1297e89207d581de1a12187c4c997522b761d511b7ec6d08c9d9259069ff3fa74fbbc175ae9ff660156daf652b4776474a347e3146d558eadaadedd1bcc34e41a124d63f6dc925908cb71dfb1e675080cacf6f180b7d1543247ce0331d4101fadd8620b1c4881c5a8e9222446b8641581d48f3ade02a0b16bdaba7d54983c709d8cb1f8644f900845a61f34a500c0dd23e2b4fde38e80c5263e5e9be04c3e7bdb7b945b7c3aead4161c3fb013c40d9e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139850);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12661");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw36015");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-vman-cmd-injection");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Virtualization Manager CLI Command Injection Vulnerability (cisco-sa-20190925-vman-cmd-injection)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by command injection vulnerability. A local,
authenticated attacker can exploit this to execute arbitrary code as root on the underlying system.  Please see the
included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-vman-cmd-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39d1eeaf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw36015");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuw36015");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12661");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '15.3.3S',
  '15.4.2S',
  '15.4.3S',
  '15.5.1S',
  '15.5.2S',
  '15.5.3S',
  '15.6.1S'
);

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCuw36015'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list);

