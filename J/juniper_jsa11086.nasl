#TRUSTED 5a8028084dc2a79e7a831a52a9593b8186b41da1a5ed875a2a10cf4ab33c86bf1f1cede4d00e13267bfee8dcddadccd75b5a36c07e1cbc1f412a1957f9f1cce70342e41dc956a4e642d40906ac65a6ad8ee88d1c295850f3db3fb5c9373efbc4e1493b2aa1d78cd01617770fb950d5e13ca4671fe0fa77eb05723ed6d1ddb94208c6da8e24c920d0550ef32811f637ff24917ede1db3e601496ed941ca020d84a4c38accef4487c7a41d8b076f27da4151485e4b5267f2ba6769dcbf56e7b245902177d94d023e86d3a43e648b37a2759f73a332bdab54a3f898c80343b0cdd59561a43e33a56b87f4dd44309435d977a70a1bb64d3d8a248a874cddd0e5255c4d6736ae774a96324b03f0025c1641800a5ac0c3aa55f3102e609cdb40a29ceb00d520c461330d5ac5defa4366d669bd296d9f7c6e58e579e7e1274a98200627473577e5c2a10f93139d78afac1a912af11756c7f6ea595bff117c211813195526a51115a3ab695766ae28bf4009a684dc590de0a14bcdba19bc8a80310e4b47d41d5e43dc7912ad70ff498740d807aaebd6319924e8546bee4a9bbe4600ae7454df1a72223531b772a71a36e3a4eda2aebd63ccbf1153925f3e73d331d88bbae2e02c5ba75f930e2b694fa4d54e7af444749d745c6d4638f82cd11de8ee0cc0c1b9df54e0e42fe2e89ecc921aeaad7f45de13bb855667f72d506b81b7dcb001
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143382);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1689");
  script_xref(name:"JSA", value:"JSA11086");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos OS EX4300-MP/EX4600/QFX5K Series DoS (JSA11086)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11086
advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11086");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11086");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1689");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (model =~ "^(EX4300|EX4600|QFX5)")
{
  vuln_ranges = [
    { 'min_ver':'17.3',       'fixed_ver':'17.3R3-S9' },
    { 'min_ver':'17.4',       'fixed_ver':'17.4R2-S11' },
    { 'min_ver':'17.4R3',       'fixed_ver':'17.4R3-S2', 'fixed_display':'Upgrade to 17.4R3-S2, 17.4R3-S3 or later' },
    { 'min_ver':'18.1',       'fixed_ver':'18.1R3-S11' },
    { 'min_ver':'18.2',       'fixed_ver':'18.2R3-S5' },
    { 'min_ver':'18.3',       'fixed_ver':'18.3R2-S4' },
    { 'min_ver':'18.3R3',       'fixed_ver':'18.3R3-S3' },
    { 'min_ver':'18.4',       'fixed_ver':'18.4R2-S5' },
    { 'min_ver':'18.4R3',       'fixed_ver':'18.4R3-S4' },
    { 'min_ver':'19.1',       'fixed_ver':'19.1R3-S2' },
    { 'min_ver':'19.2',       'fixed_ver':'19.2R1-S5', 'fixed_display':'Upgrade to 19.2R1-S5, 19.2R3 or later' },
    { 'min_ver':'19.3',       'fixed_ver':'19.3R2-S4', 'fixed_display':'Upgrade to 19.3R2-S4, 19.3R3 or later' },
    { 'min_ver':'19.4',       'fixed_ver':'19.4R1-S3' },
    { 'min_ver':'19.4R2',       'fixed_ver':'19.4R2-S1', 'fixed_display':'Upgrade to 19.4R2-S1, 19.4R3 or later' },
    { 'min_ver':'20.1',       'fixed_ver':'20.1R1-S3', 'fixed_display':'Upgrade to 20.1R1-S3, 20.1R2 or later' }
  ];
}
else 
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
buf = junos_command_kb_item(cmd:'show virtual-chassis status');
if (buf)
  {
    override = FALSE;
    if (!preg(string:buf, pattern:"^.*Virtual Chassis Mode: Enabled", multiline:TRUE))
      audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  }

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);