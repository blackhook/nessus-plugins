#TRUSTED 275fc39fbd7feb4c4f3746a5307f498ab17a23e45d45e0169c1b6d037c2bc7b3a2bd80d743209513c13d46fc4c68f2e9bdd51ed12218af35f1726d6f41c1a9ea4d34f14a0f78701ea7033dfac6037a9defeaa96f6e783c51940c90b3ae5cad0f3b509f8305a6e059be56f443e84b5e9e71dc1b38a600f086091056b1a9e964cccc59839c521cd23337059f4cf9211251cfb4a338007cc308cb847d6d92e6fc796009557acd9af0bed6a30a2fe4389b8f49648b770b144ad560bfda163db586473e90c64124c09175243ba5846d0e2ae70ce1948adb07453081314738331b9986a1de4b66afb8eff9a7b0129d51c7933b1a26c559379f5cbde824b0a7ab501e95b9b3c1ffa1ff6130f83901f2e796e6994231a3e3e7c917e1f929cbbc622e62546484ed2db1d321d61fabe236a741181f68d2c85067fbdeac79f97f5aaae6b6e18b2a9857562f70c7f1d553f959b0b0f2aa56b09713907e09b6be344b971071ddf2d022f0ec0aea135e8a604822caa99589a2d60c9d679bbb9a0fd551d70d8330dc17ff47c771bbe4172f8f4ecde4905adca5091f359e302ebb1799ac4dd0264cee84907b4651648224060ba614458ea5ff0caf91f311f29db3a0d0bcba5958740896d6660c8418f47d6b00060f39f325d1765043e2b9a57747922c1f954ffacfca785b00f7e2475fe74245210f1cdfff5c064ade0d3176b9ac99cfe33a095ddf
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141806);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1671");
  script_xref(name:"JSA", value:"JSA11068");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos OS: DoS Vulnerability (JSA11068)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 17.4R2-S12, 18.1R3-S11, 18.2R3-S6, 18.2X75-D65,
18.3R2-S4, 18.4R2-S5, 19.1R3-S2, 19.2R1-S5, 19.3R2-S4, 19.4R1-S3, or 20.1R1-S3. It is, therefore, affected by a
vulnerability as referenced in the JSA11068 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11068");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11068");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['17.4'] = '17.4R2-S12';
fixes['18.1'] = '18.1R3-S11';
fixes['18.2'] = '18.2R3-S6';
fixes['18.2X75'] = '18.2X75-D65';
fixes['18.3'] = '18.3R2-S4';
fixes['18.4'] = '18.4R2-S5';
fixes['19.1'] = '19.1R3-S2';
fixes['19.2'] = '19.2R1-S5';
fixes['19.3'] = '19.3R2-S4';
fixes['19.4'] = '19.4R1-S3';
fixes['20.1'] = '20.1R1-S3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (junos_check_result(buf) && buf =~ "dhcpv6")
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
