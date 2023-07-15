#TRUSTED 04afdd26887d9e3372d1e53cc20a6d7432638abc9ff88ae148c6fd09a5c5028a11db27cb8f72c8d028c7341d77e7af63f3a60cfe098302433be1a6c051251eed47a2a377b75ee36356dbcd8d9b7cc47c454693d160bf4758aa7bc0244a5cce98f1d0678008348852e4d394af77ef335c7b5b6bd921f9b0b5253f92dc4ccca1015a12d348f00b50927e4bfa41c273a234b2b05af923031db17ff06c3d99ccbf1d285cf6575c11c1f5a72f8e058f14ba2925771a01feb0368193feab28d5df9529d6f51c14b2163cbad9e2539ab800c0061ed1d9871871f7bb2e16c768f77ef31e19a2681fd15df7ae3ec8e6cc3a76f9a3a8db1b2713a83a98100669cc8ba38a69f01bd917452163c315231285c64b570484c0d74ad6a8d4ab863b9cd8095901b0c9982972f6daf2d66451e6713f8ab1b373ae0d30a1cba4df423d69d8b3506e635e5d4c4c547e6a2a6d9645cd73ef909f6b46c1d494068afdd1a99e32d6d98ecd12c1388799553fd223dcdbf22761de1dcc028b4d92ff6f023c9e6443cddf22d8701b929ba5db56fd42ae8a0b1fc672d9c490121f7ba941da0f88d748041f7f0dfc1fbc7200dd603e458a9227f9f1251d501e358838cc1d0e1b50d3f3f12bcc4c5fbcd164de02576375c05f10ab01f338e7459890040a2c402c9b997fac2ecea96f1424eb56a7e17a73d20bc1cb10cf84440560046a1e7eeb6c0519adf1b1b97f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134304);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/10");

  script_cve_id("CVE-2013-7470");

  script_name(english:"Arista Networks EOS kernel DoS (SA0040)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability in
the Linux kernel. An unauthenticated, remote attacker can exploit this, by sending malformed packets with rarely used 
packet options to a vulnerable switch.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/7098-security-advisory-40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc9de589");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version EOS-4.18.11M / EOS-4.19.12.1M or later. Alternatively, apply the patch
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-7470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

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
ext='SecurityAdvisory0040Hotfix.rpm 1.0.0/eng';
sha='7eea494a74245a06369ed11798bbcd13f6782932ee5586fb289ec6fc5dae4a300bc745a0aec4fb0e348d85d03c2aca37ad97c55313ced0f4c1632888944d2b1d';

if(eos_extension_installed(ext:ext, sha:sha))
  audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been installed');

vmatrix = make_array();
vmatrix['all'] =  make_list('4.14<=4.17.99');
vmatrix['F'] =    make_list('4.19.0',
                            '4.19.1',
                            '4.19.2',
                            '4.19.2.1',
                            '4.19.2.2',
                            '4.19.2.3',
                            '4.19.3',
                            '4.18.0',
                            '4.18.2',
                            '4.18.1.1',
                            '4.18.2',
                            '4.18.2.1',
                            '4.18.3.1',
                            '4.18.4',
                            '4.18.4.1',
                            '4.18.4.2',
                            '4.18.5');

vmatrix['M'] =    make_list('4.19.4',
                            '4.19.4.1',
                            '4.19.5',
                            '4.19.6',
                            '4.19.6.1',
                            '4.19.6.2',
                            '4.19.6.3',
                            '4.19.7',
                            '4.19.8',
                            '4.19.9',
                            '4.19.10',
                            '4.19.11',
                            '4.19.12',
                            '4.18.3',
                            '4.18.6',
                            '4.18.7',
                            '4.18.8',
                            '4.18.9',
                            '4.18.10');

vmatrix['fix'] = '4.18.11M / 4.19.12.1M';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
