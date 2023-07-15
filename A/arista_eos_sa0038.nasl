#TRUSTED 74beaec446cbd00929bf82185cf8551e5d188761b4532c44c08089b9bc9e959f97be9fb0e95be4da74961478cfd66c017220bf1e3a5dc08ed02a8101fc858b618b3ec4e85eb5679b75b2235ddd2c119aa2c4ca79004b916175ed45f4f2d12716d4e895a2a0b70ba55415ab1eef548306260070dc50c80d71cb2a501c79a7cbccff268e4b41e317fbb2969125b6acf12b91a785c676f671f9bb15e231a1d40d6248c725042af08031dd3949d91ac0e338a645c7d3546f934fb6db7ddebbffd8d93f0dba15bce46e4053413e928dfdc019ab91837f55348b7c6e05a5efd01d94235fbd875d8e6f4405d002bd972882e557ead0efc6e533f92f7f35a881eb23105bd34227273542ca1c4ca03439d3af26275b40f7ee45fa58214bb973694e9af57e58d337b5d6b87e8a5e8dd06046dea2edfe95cee0cce7b57a650b3e45858bba601c6541d26bf29c850580f671eff29ea247670dac49ec4cbedc83b217482c34aa9451846b50845ac5b5f66e274f636a2f4bb84daf6d0278ed3003ef68b8799de9a3ce1bcdf7894d3ec8b931f4f43c7a7c2f327d8fab002af5b1ffb08157bc95f322b245dcdc6a6265d743e05b5b9e4ed0f295a5f7d3b1bdd7a574fc0050b13ac97afaa2365273637f1face43a11566a5f9c4e06e8bc0a968407d6037c8cdb163d972762068bd56b8315823240e8bca257ec28fa549920f1d9b7c8233dbe89262d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133959);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/27");

  script_cve_id("CVE-2018-14008");

  script_name(english:"Arista Networks EOS 802.1x authentication DoS (SA0038)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service (DoS) vulnerability
in the 802.1x authentication feature, and by extension MACSec, when dynamic keys are used. An adjacent, unauthenticated
attacker can exploit this, by sending a crafted packet from the data port, in order to crash the Dot1x agent and cause a
DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/6072-security-advisory-38
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d7ba876");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.21.2.3F / 4.21.1F / 4.20.9M / 4.19.10M / 4.18.10M or later. Alternatively,
apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('arista_eos_func.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit('Host/Arista-EOS/Version');

if (version =~ '4.20.8M($|[^0-9a-zA-Z])' ||
    version =~ '4.20.7M($|[^0-9a-zA-Z])' ||
    version =~ '4.20.4.1F($|[^0-9a-zA-Z])' ||
    version =~ '4.19.9M($|[^0-9a-zA-Z])' ||
    version =~ '4.18.8M($|[^0-9a-zA-Z])')
{
  ext='SecurityAdvisory0038Hotfix.rpm 1.0.0/eng';
  sha='3f764e58f7b090f5ad70d51e080298f753907578f2a41f998a2dab18304fffc6d329a600dc8b32e3dee1ebf2ad202116f663c6909c2c690581ca393746b4247e';
  if(eos_extension_installed(ext:ext, sha:sha))
    exit(0, 'The Arista device is not vulnerable, as a relevant hotfix has been installed.');
}

vmatrix = make_array();
vmatrix['F'] = make_list(
  '4.21.0',
  '4.20.6',
  '4.20.5.2',
  '4.20.5.1',
  '4.20.5',
  '4.20.4.1',
  '4.20.4',
  '4.20.3',
  '4.20.2.1',
  '4.20.2',
  '4.20.1',
  '4.20.0',
  '4.19.3',
  '4.19.2.3',
  '4.19.2.2',
  '4.19.2.1',
  '4.19.2',
  '4.19.1',
  '4.19.0',
  '4.18.4.2',
  '4.18.4.1',
  '4.18.4',
  '4.18.3.1',
  '4.18.3',
  '4.18.2.1',
  '4.18.2',
  '4.18.1.1',
  '4.18.1',
  '4.18.0',
  '4.17.3',
  '4.17.2.1',
  '4.17.2',
  '4.17.1.4',
  '4.17.1.1',
  '4.17.1',
  '4.17.0'
);

vmatrix['M'] = make_list(
  '4.17.4',
  '4.17.5',
  '4.17.5.1',
  '4.17.6',
  '4.17.7',
  '4.17.8',
  '4.17.9',
  '4.18.5',
  '4.18.6',
  '4.18.7',
  '4.18.8',
  '4.19.4',
  '4.19.4.1',
  '4.19.5',
  '4.19.6',
  '4.19.6.1',
  '4.19.6.2',
  '4.19.6.3',
  '4.19.7',
  '4.19.8',
  '4.19.9',
  '4.20.7',
  '4.20.8',
  '4.16.14',
  '4.16.13',
  '4.16.12',
  '4.16.11',
  '4.16.10',
  '4.16.9',
  '4.16.8',
  '4.16.7',
  '4.16.6'
);

vmatrix['all'] = make_list('0.0<=4.14.99');

vmatrix['fix'] = 'Apply the  vendor supplied patch or upgrade to 4.21.2.3F / 4.21.1F / 4.20.9M / 4.19.10M / 4.18.10M or later or later';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_NOTE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
