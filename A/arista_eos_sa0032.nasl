#TRUSTED 90bfc42f4233e820ff12ff77268b94947bd1f1bdbe77125d61cbb51971990a85d8964d0531e69963c8525ac1b93e1c2e279222948658b0049eb07676a763946358ce923923d31d7c609dbcf926962344c666e006f5b83fc516e4c1a9ba0e97584270b8189c3d5b848c876c51e8b044816f86fafdc73e4f3800def37af038f8e8ad25295fd277af60a43388d5cc5d80f21c1cdbfa5653c9b9a46aef43d93cb2434c9ba0d92dc5e7ec9161e8f3f4a65213509c8d8fc76aa783455628ef13f480332586d8d46cbc6b3f2a1d9a38271b9c4e282589e4102e79ae3625e2d04f4827a55a1439e1c81d9c17b063dd406f6d3768f74b49057ac7fd6f6f455b56b39175434668f93a8c48710f26a68c14261775ca29949b5a5211dfc8ef9e268614a4ca0ff41c70e5974d3ba577e8214d355ef1f3304fad832435a68e3f99684168142eadf4e92a9d87f7b271e412d758f22c96ffe00b0fafd905a1861ff1960b596d091fa48f98af7cae9d627b368bea96a8fd26553d7cf8a078bcc8cbe99877ba900ad2bb3f00363556b897fbed730eac7f228d70de2822a7051f4ce446ab88f67e2edb2b15aaa3da6ce4bca323c542cfdaafffe83caa490c178d20faee25e55322ec58decf96d958e3b490dc5b9e09955634d32bff672ff00b241d101a677b2680f43b6e92da5f235e47938004f7137f90742ca573c30026d92f274d3a618654c5c15c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133852);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-5255");

  script_name(english:"Arista Networks EOS Mlag agent DOS (SA0032)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service (DoS) vulnerability
in the switch's Mlag agent. An unauthenticated, remote attacker can exploit this, by sending crafted UDP packets on a
specific UDP port destined to the switch’s IP address, in order to cause the switch’s Mlag agent to restart.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/4347-security-advisory-32
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbecd1a4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.19.4M, 4.20.2F or later. Alternatively, apply the patch referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/01");
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
ext19='1.0.2/7374832.belfastpatch234146';
sha19='d7bf406e9ab06958d632cf0737022a4c7b59e8826e9c2ed1fab85e2adf15ee753b6245a2f94d90de0e0d97b05d3b8f4ea3c6d65526b03c9607dad9bf0d8dd83d';
ext20='1.0.2/7318675.vmahadberlinA1patch234146.4';
sha20='bdf51eb62a26a89ea352d9f71d9ee13597f0b269abb5ec2af652cbf478d7aa6a7d4ad2c584a94751f646cfc6b753bf92bf022ca9fc9c459291e016e7fa6fe4a8';

ver = get_kb_item_or_exit('Host/Arista-EOS/Version');
if (ver =~ "^4\.19\.")
{
  ext = ext19;
  sha = sha19;
}
else if (ver =~ "^4\.20\.")
{
  ext = ext20;
  sha = sha20;
}
else
  audit(AUDIT_HOST_NOT, 'affected');


if(eos_extension_installed(ext:ext, sha:sha))
  exit(0, 'The Arista device is not vulnerable, as a relevant hotfix has been installed.');

vmatrix = make_array();
vmatrix['F'] =    make_list('4.19.0',
                            '4.19.1',
                            '4.19.2',
                            '4.19.2.1',
                            '4.19.2.2',
                            '4.19.3',
                            '4.20.1');
vmatrix['fix'] = 'Apply one of the vendor supplied patches or upgrade to EOS 4.19.4M / 4.20.2F or later';

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
