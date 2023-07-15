#TRUSTED 4ec33fa96876a466a5aeb3c6bf0317c886925335aa167d6b83eb35ae041cdcfab195561e6d7eaa3d7403789c571bf2452c83fcf789cbf00c7b0338b83145b6b913afa99685b7e6723aff86241e3e612341da4de8760abe91e95cadca90dac8292d2cf858d5ccaa49e45c92f39ca6cc308f6e00d0750895e4c8b973abaa4b38a4e880aff6cc91c486d8be7757c13feb85155e6e869783c03b3f8e04124b39f94e063fd19b5344b6f3df2ec35a954724c776743a854a399874f499585d5b120372e59785e022ee49be7a8223677e49f61b3ed47752e3b8ef2a7d1c8f1a8324cb23c466a28966b2d88abce0d0ca7c5e666a9e8a835d445c687db089b48df465c85e1bd3678b9179e37ffa136f95c3dd6c4adb7189347c9589b7c11d34223769009334a09b1854e24fd45a342ec298f17078b6c2a48f3eed395acc4a38e5711f58bff12f7f8e5c716d7bbf80fb984a7dcd378f5431e23ecbd4b684f8b3847d6fbb5166cf97ff459be1ee8ded159ee1cb215021c1098e87bbfc2a2d95d0c6651faf07d85de0bc722acba625970fc55fd650c69994eb888a5b780e5680b3232f3ccf21399102b4d8c51c47e6cfa31e6b0f6efbfa3156b9c0b0973a406f2cf87dccbaf0ec968f6e2920b31a1a9fd8333a20b13a5268e2579103e48da914084d68f4163197b7ebb893ded735d5ba668428b1d3b4bd9f630698fa2fac51b004453acee3ec
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134418);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2019-14810");

  script_name(english:"Arista Networks EOS LDP DoS (SA0042)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability in
the Label Distribution Protocol (LDP). An unauthenticated, remote attacker can exploit this by establishing an LDP 
session with the EOS device under race conditions and sending route updates in order to cause an Out of Memory (OOM)
condition that is disruptive to traffic forwarding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/8321-security-advisory-42
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50fff6f6");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to a fixed version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Host/Arista-EOS/model", "Settings/ParanoidReport");

  exit(0);
}


include('arista_eos_func.inc');
include('audit.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version = get_kb_item_or_exit('Host/Arista-EOS/Version');
model = toupper(get_kb_item_or_exit('Host/Arista-EOS/model'));

if (model !~ ".*7280(E|R|R2|R3).*"  &&
    model !~ ".*7500(E|R|R2|R3).*" &&
    model !~ ".*7020R.*")
    audit(AUDIT_HOST_NOT, 'an affected model');

ext='SecurityAdvisory0042Hotfix.rpm 1.0.0/eng';
sha='c94c650c46211cbdfd591865afe7b991b963fa3e153c2d1bb5174febb09160c4fc4bab1b8e08ba437f881a1df79aa00e86c854d5a9fa0e703c0baa15e25fb89c';

if(eos_extension_installed(ext:ext, sha:sha))
  audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been installed');

vmatrix = make_array();
vmatrix['all'] =  make_list('4.22<=4.22.1',
                            '4.21<=4.21.2.3',
                            '4.21.3<=4.21.7.1',
                            '4.20<=4.20.14',
                            '4.19<=4.19.12',
                            '4.18<=4.18.99',
                            '4.17<=4.17.99');

vmatrix['fix'] = '4.23 >= 4.23.0F / 4.22 >= 4.22.0.2F / 4.21.2.4F / 4.21 > 4.21.7.1M / 4.20 > 4.20.14M';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
