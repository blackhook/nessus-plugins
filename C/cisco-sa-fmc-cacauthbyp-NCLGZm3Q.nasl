#TRUSTED 469451a8277b3ea9c71a325c7a5e967df23ca3a6e0449f9472b662a955a3eb05e405b44d005ab738c6dd872bf5543e3c91ac33564daed5047aa8a6788fc5add4ce62dd147af2325056d2cc3a706b493c3b763deae31cbcdfc6cb9a4722f221cfcf2f8f4bf6ccd7a699db7b9ed84fcac1b92ced95e71770e68cbeb8e29dda37961de91c10006f4695835cc61f4e07dc8cf9ca17baded5a06af06b47b4f3977bc6682215ec6da95e573456933052b5911a9c0a92bd9bd20c7d10ac4df83179b1ef4de8bec15d8c46ce50e66c01ebdb773e51a98fec679f09abb10d6ec7184aec7500bd59117c8f8e3eb4a813b1c66f1ecd1680748442ccaabd107ee8bb1154772a05e47e33f0faae637856825dd33d6525cdadeb19c7a8f4290cd49b23a7c4ef3a5c930554a52f6a074618a9da84362b8901897b24302fe9f9894b8b71e1790dd69ca3afe4f48b2723fd76c3022c5539d250846c212ab4e5224f337460f59422cbbf26f35b255cbd5081cd3b785f63cfc5899c2261d81200e526bfe8abd657dec7b7e76fb12aa012bea5dbe9f77d22a1468e83cdeaa5ab3d3b4cd9cbf2423af5ce80490e178874a14094eceea48ab165c5bcf03f71d3ac9174f7ddae734d046faafe588dd31404a6e741496a0992519a4dbd074db0ecf237fd441c31c7de87648ff8695f39d70832d4a40ed9065789c49e331a92c5ad2ef80b82d27d9d05a7453e
#TRUST-RSA-SHA256 421b3b9c08d7db9e48a946e7fad7c45480f32ad23cb3edcf81c8e3b6e66fb81ce7ec300178cead5d223dcae0f9237119e2383363acce6ead792ef583b332e7ce58c18ddc30755349f604eeed4cfd6bab5169ff0a0cd69c607083f6d4e7bab84a832c4c8da24223b366ed5431efdffb5c917a62f921c758154b09903aa01e2dfec4a388771d0be20aeabcf20675575c5e77cfbd5f2b3af2bce4aee38b0b7d43b42fcdf56ba369e75a815252b401e2180b4b8ccb9b6492cc4058b340c783bdbf697da8f4eef79e2b8d449c2014ba143ba859acc917f2b63eebbd7790c5aad0de2f4bc4a939a84b914bb43d46441e3ee6f6e6e6544266eb0cfbbaea9e031f94a6aa9926a996262a7e293f8f7714dd02ee1c646e8979f8f8d164fe388fc5b26ac6222f769e1db661b2f05e5ac4986a04b11cd2c0bfc4cce7a3c8e8fd386a4ca90fc3552db3cc33d32e04dfefcfb05ffc315db4e1f0d26ac0b54bb3b0b7ceb746f2f70d0e9d34379d8c8bd93480d75cc2172977e504d02e8521857388a0271f5fcf88eca4a410d2947c8adc42292e7a42ff2c5b4f0e3502a9ee379cba9072f11b7f647a789747b5ad9024ea82000fafc50a72a507a75eba2e2cb1d7edaa4b81dff7c3b2aa3a83dc7a844fe831ad60f1f569334375354995d89c213df518bad91e08c34c21d47948d197be4e46e27d9d11ede6ba863ff2c27484c861a2632886813c70
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152390);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3410");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv16245");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-cacauthbyp-NCLGZm3Q");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Management Center Software Common Access Card Authentication Bypass (cisco-sa-fmc-cacauthbyp-NCLGZm3Q)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Management Center is affected by a vulnerability in the Common
Access Card (CAC) authentication feature of Cisco Firepower Management Center (FMC) Software could allow an
unauthenticated, remote attacker to bypass authentication and access the FMC system. The attacker must have a valid CAC
to initiate the access attempt. The vulnerability is due to incorrect session invalidation during CAC authentication. An
attacker could exploit this vulnerability by performing a CAC-based authentication attempt to an affected system. A
successful exploit could allow the attacker to access an affected system with the privileges of a CAC-authenticated user
who is currently logged in.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-cacauthbyp-NCLGZm3Q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41bc9847");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv16245");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv16245");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3410");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
vcf::check_granularity(app_info:app_info, sig_segments:3);

# Not checking GUI config check
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco Firepower Management Center', app_info['version']);

var constraints = [
  {'equal' : '6.6.0', 'fixed_display' : '6.6.1'},
  {'equal' : '6.6.0.1', 'fixed_display' : '6.6.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
