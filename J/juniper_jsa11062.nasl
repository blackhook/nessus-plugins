#TRUSTED 98a0c3c232f7d82dc20702186da6492a081cc9ac0654a882993aa89939035a68f741a8a483530a73deeaacb815ab6312d82bc80a45225a68af40fc9e2426ffed164622f6340feef54bc3a0e18d255b11ecae5fa343856688532b00f8f91cba07209a24a5bc33766122d3c090f98fbf0e811f16085ee2f92562052cec611ca83a8852d5d09b3a388d7c29bfd4b6d21de1eb11d002e11397f21e39ce9fe04681ace9698881ae05855ce574f891d2923d2c57ca3a20e2cbc733dd8ad8dc473dc93abe0c52ff9939befc2d84fadb0227fc08e62649e240b14c97f181307abf3052f86251ba7176d4dd2b4b5301e71c9a568ea6bfc8338f58405187c17ac3c180d0fade1679528694063f0cffaf3c609b5a03b4fc992618130261f6fa8ec89a2913cb7c57a3068051bfb420967e2cf3f1ee78080477092dc5d7c6c867ff90228e4fb7d8110245399f6656c20b2da2dbec26d61cad5d6149b88d56139e6da6426ca3541d65e93a8d3e369fa2615ec4d6f8c2e27f70e50cf97188a08829052a7d189a4394f386dfe089f59719920618f56a2f6fe4858544895be526359d9aa0d1a56d625a5840daeffaf5c9d2dcd8234a51bf86b3ef8a0bffe0d2fd695ca6cdddf67d48b7b7b1fdd898541306d4f3ed7b2bc1ff4bcb82aa58d6b2dd768ed77506158a6039f52c3403ada0951f66887d9378f53bc30edf42f12393396d6e6f4dd6ff9d20
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141827);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1665");
  script_xref(name:"JSA", value:"JSA11062");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos MX/EX9200 Series: DDoS Vulnerability (JSA11062)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is MX series or EX9200 series prior to 17.2R3-S4, 17.2X75-D102, 
17.3R3-S8, 17.4R2-S11,18.2R2-S7, 18.2X75-D30, or 18.3R2-S4. It is, therefore, affected by a vulnerability as referenced
in the JSA11062 advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11062");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11062");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (model =~ "^MX" || model =~ "^EX92[0-9]{2}$")
{
  fixes['17.2'] = '17.2R3-S4';
  fixes['17.2X75'] = '17.2X75-D102';
  fixes['17.3'] = '17.3R3-S8';
  fixes['17.4'] = '17.4R2-S11';
  fixes['18.2'] = '18.2R2-S7';
  fixes['18.2X75'] = '18.2X75-D30';
  fixes['18.3'] = '18.3R2-S4';
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
buf = junos_command_kb_item(cmd:'show ddos-protection statistics');
if (junos_check_result(buf) && buf =~ "routing engine.*Yes")
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
