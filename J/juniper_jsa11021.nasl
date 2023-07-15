#TRUSTED 03cf3994d798d906aefb96930dc173972435cbdf6ed7f1fbdc0c0874a0f495edba7fd7647b151ac1d1fbb64ee5b41ce8432e559692bebb7c6b044af3a8dfaa56cea044c3d089417d500198fb751701b9a6963ec4632d57438665137d91b157905472acdbbde606e99b1335e02cd6d317564cdd590547dcee7ee22864b8e7f030be825bc12b50ca12e4a6e89b0c14a29f5867ca0eef38a8e3ed9a95a3aef6a60ee5ed2d12c3dd3c531abadb63f684ec41ba2c78415118f2dba84f2e07c0c63aa7fc1c27d46e6d230a409df231248d1a629ef2ae1ada49e97bf5b7c097b754bbd59a443ae437bbb3c0561aab2de98f5d4460298de86d4efdc87708a6b4325f0b0ebe30093e359b05d2b51967e51c257251fad9f609d8078e0868e75b1a2c62bd12e22478281a665337e5f89b6aedc18f55bb5d14d49f1437ecc2c40f8479ceccadae2d6fc55a2fac29abc994648c1b47e2daf0537615286d1ba338fc7eee4c87bc367357af52935801869a740fa2b59166f14db93e514c751109dff487f89c0d5cb78aeb52189a344d07b5935201dd397939c390d8f3f5f210b56d91baea0803c4005b765d38bb36b1716894c5063bc055f84dad9470923f4ed1eb511bf0cb20226230d6480d880ed729641a3473b7d00ab1a1fe10a40c99c7fd3cc5b26246a67c12afb57a143d1291c1edd9ff5c0af7154f0f1641f72da0f2c4189ceba9d3bd89
#TRUST-RSA-SHA256 02cec00765d01d87b16b9ebd5cb6946f97349aa43aa8d969f3daebdde4981de99964dd7edbe131db0ee71ac78585af8ac94bb026f959c5a360d8e1c19bdbecc514ce53cb70af54c72d44aba3a390b7f24ba14f934ac273a5ee2882733dd6eef1f16f8e9216a9418df39482ee9078d2bd95f02192c588cb655c5ea191fee93d8a53174750f3ce360519fb56b15dc523074475c0ba6aff6e57dd88db93ec446d4ba31e4d5b98e76e2aed3a8cb48f9e4eb2f9ed2390330d59432099fd325d88279e46d4eb55876e0e0acdf4f96dff3da7636ec3d68b60c4b335ba2fa3bb7d3248083ef3cd861e7139b57e1b9e1fd653edda4dd3ce535e13eb60ee19ca7cfb0d7f7722de0b25da57c5c02ac159532b0b04dc0eda77d88fc3163d12b701903dc072d6f7845df5b56aa646657b5a7f6e48fd356c0a873980e10280ea7e27b06890dcc8e2721e9274206258e727de69f948281f0bfd96116ddb416acf33102c6652b5b5f3e656bc3c28b8c5e7630b351c4b2f7a722ef308c0c89dc67e686b2dd712660f889b229491fcf7017ef81163f02f38b1ff3540c46050b75d910b5e9cc5c0a6f27b8a47cfc1d28dd6a66acce3c6c4493dcd68996525b49d1a2fd9fa46acdbc8c7610bfbfd335243cef9131c0b23ce7d51dd9f605c1755af3fbb35c5cd95dfe6bb98f942fc24a67e47442273b60b1448fb95f210a6e77066c433bde30ca53453b8
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136285);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-1631");
  script_xref(name:"JSA", value:"JSA11021");
  script_xref(name:"IAVA", value:"2020-A-0181-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Juniper Junos Local File Include Vulnerability (JSA11021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device it is affected by a local file inclusion
vulnerability in HTTP/HTTPS service. An unauthenticated remote attacker can exploit this to perform local file inclusion (LFI),
path traversal or maybe able to inject commands into the httpd.log, read files with 'world' readable file permission or obtain 
J-Web session tokens. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11021");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11021");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1631");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.3']    = '12.3R12-S16';
fixes['12.3X48'] = '12.3X48-D101';
fixes['14.1X53'] = '14.1X53-D54';
fixes['15.1R']   = '15.1R7-S7';
fixes['15.1X49'] = '15.1X49-D211';
fixes['16.1']    = '16.1R7-S8';
fixes['17.2']    = '17.2R3-S4';
fixes['17.3']    = '17.3R3-S8';
fixes['17.4']    = '17.4R3-S2';
fixes['18.1']    = '18.1R3-S10';
fixes['18.2']    = '18.2R2-S7';
fixes['18.3']    = '18.3R2-S4';
fixes['18.4']    = '18.4R1-S7';
fixes['19.1']    = '19.1R1-S5';
fixes['19.2']    = '19.2R2';
fixes['19.3']    = '19.3R2-S3';
fixes['19.4']    = '19.4R1-S2';
fixes['20.1']    = '20.1R1-S1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for NG-RE, if not output not vuln
buf = junos_command_kb_item(cmd:'show system processes | match http');
if (junos_check_result(buf))
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
