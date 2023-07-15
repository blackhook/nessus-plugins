#TRUSTED 75d096f0e101b43cd370344df731a762618258e3ec7b43773425a6b4679ff1f9473cc74ef73843dc9611c5d70d10c9afcc4425cae62f19bc8f75b205edb080650430551fd174ddbfe93383029f4ea6f573e40af1588d803fe283ed16f7af821d409f730b1f403dcc41c64c564d26a74d93c080e5e5cc254f5f3d15ce682a171a887989f48128027e3e23d6134c6fad835bbf3e85d89782a645519d6a51763e75771e8c6bbabce2e11142af034d8aee287f70a3ed223f5de1f5eb85c6407c04c0fa88a9d53663f2ebbca12357485815a139e50b27c5aae3d2f354de98adb6807c31b247048f9df29065e29254cd37683b846129cfa2ab261a7c306ffec6b7304bf7fdb14098c7103438c149f6fe507511b8ade865161c11995e01728d68a46a9da5f97b43823c51732c7340d3cc4988f92287a54cf4908863048de46b3aaea8a40a07345efa77347d3935e3e14e6f0c8e1925dbe084d86b9dab07e9aedebc608b00be8794b857def17be2c93067048f7e9aec42203d84ed8f1c7c47bb7716c7ff6d0dfee6a98fb80b7ddedbe031462cd32233f12f9940724d32b3b48f6f3734d3727855bbea1c8b23b58f6304dd8f8a3fdd8fc932f158fa91a38bee1b4bf5aa5a8fb460dc02e257d638bf578504cca96682028bf4cf36dab6755157311bccc413f16a68bc8a66db6281255054334f2d4ff700699144cbf2a2d166b077683f4cf3
#TRUST-RSA-SHA256 55a4df7dc7ad8d1ff003aa9f59345f57924ec1e6b0f4d9b7c33518b3b4f417242a5d6a5003da3cb69a5a78cfdbf12ebe933264d2c3b07001ca7dbc0e056de1ef31b465e06179dfab341fd505df94ff11c7fd56657ded9ff353100ab08f95276d333c83c19ee8fd2683144d1533f23774697f0f5548fb0a8a4d1b6b4169d80fd563f349ac54801c48e4265c71593f0d27f6452875858128cf8e471d74749e9ccf0b0b3f6cce0e61b7f385686819b997a1d14419b6ceb65a891ae9b38b2f3185418f6d3ddb50e595b3ba61e21130717a864d7272c487c37f7173399710bee42fe1ea1b148cae6852aea8dcc2719d8fd3313272a68f2d498732fd2f4f50e8a7ff78c6bace642f670b25f6e4295e250bd269306331b65b6269ed02e2fd65960016d91cc4a0f8789aaf1a59e50b40fb50df2f7ab1ff139f6fc8621b9bb09a04c8bd99a10b716050a3893b9887a13748cad7e097779159d49147bcb947b88280f0042e1b377c251425bb1edb28a172b36426273ea08b18216d552712bd7621116d1c8f8030c558f87922f906fd3d06e2c647546a810c28dfa6d231797a9446107da7b3315131a8a401325239b7c732f72fd8a98db0d59cf76727f56c197833c557d6c573725f942175c2a5c513d24624eac0dd2497503c5a3b47d654e49e8261b25af6f7bec855e0798e7dad157a18ea71ee9fb0481d295575fa0c99392ab5846255b2
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159517);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2009-1154", "CVE-2009-2055", "CVE-2009-2056");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtb18562");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20090818-bgp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol DoS (cisco-sa-20090818-bgp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software with BGP enabled is affected by the following 
vulnerabilities:

  - Cisco IOS XR 3.8.1 and earlier allows remote attackers to cause a denial of service (process crash) via a 
    long BGP UPDATE message, as demonstrated by a message with many AS numbers in the AS Path Attribute.
    (CVE-2009-1154)

  - Cisco IOS XR 3.4.0 through 3.8.1 allows remote attackers to cause a denial of service (session reset) via 
    a BGP UPDATE message with an invalid attribute, as demonstrated in the wild on 17 August 2009. 
    (CVE-2009-2055)

  - Cisco IOS XR 3.8.1 and earlier allows remote authenticated users to cause a denial of service (process 
    crash) via vectors involving a BGP UPDATE message with many AS numbers prepended to the AS path.
    (CVE-2009-2056)

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20090818-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2554a1bf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCtb18562");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCtb18562");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2055");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['router_bgp'];

var vuln_versions = make_list(
    '3.4.0',
    '3.4.1',
    '3.4.2',
    '3.4.3',
    '3.5.2',
    '3.5.3',
    '3.5.4',
    '3.6.0',
    '3.6.1',
    '3.6.2',
    '3.6.3',
    '3.7.0',
    '3.7.1',
    '3.7.2',
    '3.7.3',
    '3.8.0',
    '3.8.1'
  );

var cisco_bug_id = 'CSCtb18562';
var smus;

smus['3.4.1'] = cisco_bug_id;
smus['3.4.2'] = cisco_bug_id;
smus['3.4.3'] = cisco_bug_id;
smus['3.5.2'] = cisco_bug_id;
smus['3.5.3'] = cisco_bug_id;
smus['3.5.4'] = cisco_bug_id;
smus['3.6.0'] = cisco_bug_id;
smus['3.6.1'] = cisco_bug_id;
smus['3.6.2'] = cisco_bug_id;
smus['3.6.3'] = cisco_bug_id;
smus['3.7.0'] = cisco_bug_id;
smus['3.7.1'] = cisco_bug_id;
smus['3.7.2'] = cisco_bug_id;
smus['3.7.3'] = cisco_bug_id;
smus['3.8.0'] = cisco_bug_id;
smus['3.8.1'] = cisco_bug_id;
smus['3.8.2'] = cisco_bug_id;
smus['3.8.3'] = cisco_bug_id;
smus['3.8.4'] = cisco_bug_id;
smus['3.9.0'] = cisco_bug_id;
smus['3.9.1'] = cisco_bug_id;

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config'),
  'bug_id'   , 'CSCtb18562'
);

cisco::check_and_report(
  product_info      :product_info,
  workarounds       :workarounds,
  workaround_params :workaround_params,
  reporting         :reporting,
  vuln_versions     :vuln_versions,
  smus              :smus
);
