#TRUSTED 35ed6d7eda7f0e380067568fa1273ab4a14009e5c6dd49871f63d2084f01dfe7ad863ec8d5afdf06da14a37498960f39aa9b6ed7b1a7b9d19ba2cccd9fb1e73d30ba9166dc6f653ee709c07a9f8faecf3331f76a47079b09c7d46f504cc7cb9c1ec96b14e8acd82f75f65ccdf22bf1633c0783bada1130953c09de0c0e034e558731ee34cf0dd75c3c275b8e020f3413c2790a4d7441508ea22fe2bc3dea853fa5ebf757707b7d19baf0dae1ad50ecfddf280defb8427f6da8e3a328f3284482274fb1a67ec206ab59491074662f911ca167bbbd3bc362bc30e2fdff365ab85f3c3f57c66ae34761225a6f1378542c068fff227af5be4b369ffb594aec6b3995e6a0a2e5e1bc44e3ec35b9ddcfe19210dc5dcd962d9695b90f39b150cbe667609cf26d316010f0800af8591533a7a9e16d124529fcef55cc50dd7a197f29e71fecb5083cbc822cf2e40dc39a37d6a71a1a7d9fa92dc558f19f0da99d7304ca3a504688be5d47512937494216421876860f6f707813154520f1b4673bddf2bb298e0c1b3824a374d6d00d59e42af51d5ff3fbf986f212bb6a4156384ffde62ee2526565a7ab5c4fafff506edb663125a9a97eb57bd515bba22f52f2b1973e6ece96e21459ca18ae144ff60184d930d7291dae86734b8bbd765c85cb0afa5ef7d71fb1ae695903f00691009fcfca3c699c1b3468b26aac1a01d78e64809b10575e
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141846);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1684");
  script_xref(name:"JSA", value:"JSA11081");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos OS SRX Series: High CPU Load Utilization Vulnerability (JSA11081)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is SRX Series prior to 12.3X48-D105, 15.1X49-D221, 17.4R3-S3, 
18.1R3-S11, 18.2R3-S3, 18.3R2-S4, 18.4R2-S5, 19.1R2-S2, 19.2R1-S5, 19.3R3, or 19.4R2. It is, therefore, affected by 
a vulnerability as referenced in the JSA11081 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11081");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11081");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1684");

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

if (model =~ "^SRX")
{
  fixes['12.3X48'] = '12.3X48-D105';
  fixes['15.1X49'] = '15.1X49-D221';
  fixes['17.4'] = '17.4R3-S3';
  fixes['18.1'] = '18.1R3-S11';
  fixes['18.2'] = '18.2R3-S3';
  fixes['18.3'] = '18.3R2-S4';
  fixes['18.4'] = '18.4R2-S5';
  fixes['19.1'] = '19.1R2-S2';
  fixes['19.2'] = '19.2R1-S5';
  fixes['19.3'] = '19.3R3';
  fixes['19.4'] = '19.4R2';
}
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
buf = junos_command_kb_item(cmd:'show services application-identification application summary');
if (junos_check_result(buf) && buf =~ "Application\(s\): \d+")
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
