#TRUSTED 1dc3817f25b5647695f6b3b50cd46c9be469a99056a9b6302b4fdae4a8aef3165c23730aa4b56135d1fd6e8b958ac32deca570e1e1fdca1d1ce75d25067ddcd1d6219b733d772f8a73ff397e0339244cdfd6e142011db4b33e007bd975f8983050987bac9cf2fa0a709d4a1485baf726bec1677f368d799e4cd2d26e6e6b4234da606d44ae22a119574b1130deef39e99d50b5532f95f7adfe5a67c8b4b5a0beb04422efbda190a9ab7aa862a075a1748d552f3a65b86bfa4d6078e77d78af7df87f8bf6ca373c2079926e1821aa66a442782ed94874de6836156df82acacd315ac667720100f9c4cfee0860f251492555414eaba57d23a60e3753335b8f8c7dc4e1c628c6739f98d24d62dbf13cba9dd3f6d4b967f66c150baba5c5baf681a6d9f112fd47c038f7eedb4d20c133bc7b5311c038c824364f4198ec100d1d76d698c632d9c5db8eb5ac8868434b6dffe6b2fe1e09bf35cd8e3e6b13da91a3f507b059e974cffb529555a82b9f00fb57a4052c550e8ca67a0a1cd647e4bfb790b3829906a91cbea3e4c27af9c6bf18f1a663d2c0eb1cc40b6f6b771c3ccf69fe314377bcdc244f9301cbd0b4538cbee2b5c5936c4420ebc267d0a63801a3ccd9f14b3d0a664bbcb79e4074a0d51e5ee3838d426e8cfbe80715b2618c81e22049f159a6c0d22484e036a697708d04c03e58ae97549ce76ea704ff40291a94c7c081
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133862);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/25");

  script_cve_id("CVE-2018-5391");

  script_name(english:"Arista Networks EOS/vEOS IP fragment DoS (SA0037)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service (DoS) vulnerability.
The Linux kernel is vulnerable to a DoS attack with low rates of specially modified packets targeting IP fragment
re-assembly. An remote, unauthenticated attacker can cause a DoS condition by sending specially crafted IP fragments.
This vulnerability is caused by the increase of the IP fragment reassembly queue size in the Linux kernel.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/5782-security-advisory-37
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c910c33");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.21.2.3F / 4.20.9M / 4.21.1F or later. Alternatively, apply the patch
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Host/Arista-EOS/model");

  exit(0);
}


include('arista_eos_func.inc');

version = get_kb_item_or_exit('Host/Arista-EOS/Version');
model = get_kb_item_or_exit('Host/Arista-EOS/model');

vmatrix = make_array();
if (model == 'vEOS')
{
  vmatrix['F'] = make_list('4.20.5');
  vmatrix['misc'] = make_list('4.20.6FX-Virtual-Router', '4.20.1FX-Virtual-Router');
}
else
{
  vmatrix['F'] =    make_list('4.20.0',
                              '4.20.1',
                              '4.20.2',
                              '4.20.2.1',
                              '4.20.3',
                              '4.20.4',
                              '4.20.4.1',
                              '4.20.5',
                              '4.20.5.1',
                              '4.20.5.2',
                              '4.20.6',
                              '4.21.0');

  vmatrix['M'] =    make_list('4.20.7',
                              '4.20.8');
}
vmatrix['fix'] = 'Apply one of the vendor supplied patches or mitigations or upgrade to EOS 4.21.2.3F / 4.20.9M / 4.21.1F or later';

ext='SecurityAdvisory0037Hotfix.rpm 1.0.0/eng';
sha='5a629438fd9988bb2ad8ece630355a033997200febf723ab531825f33b355c647b14957983fda91a131c6dc1d31f78fc0bee8fb092e6d17d6c9036921f7e6849';

if(eos_extension_installed(ext:ext, sha:sha))
  exit(0, 'The Arista device is not vulnerable, as a relevant hotfix has been installed.');

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
