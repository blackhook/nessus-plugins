#TRUSTED 703c94b06de9e201a8f081cff4a039853bd5530429cfec99b8dfec129198a3a2d7e6939bfa6c272baaede8d8ed8009828d73901c2469e9c5e704d86b30fed2ec09054074026b82895eb8574626837ecc5a5ed27e85c708568a918b62a6b6faf8030d408bdf0c68a3a88404cabdda675dad4630ebe7a0184cafdef61fbbb29d2e59c938fbd9ff62103375c2c48d4f88612aaf719ae20604a19d3c3d6246ba4e594e43d93083e5deebc716bc666ac7169cd39ec9832c212ceb74fb5c1d09472fdc1d96a983eccf50a9b8280e8dddcd623b947dd519dd4ddf65655eecb6d29ac59421fc8c1850473bdb8d8047d1179c4b8f0bb5bbca6032a4862525e21e736179507929ee7108beca2ea99cd956b49c80e1ce300d2f03d9ba92564d190a6f19445d31ef3ed38155f486ccb4e778cec86d5bb8aaf44fd9e002b02158474703f211969b41a22945ceebe189b2a8d94f1378b537e9b55004c9e027039463a0ab9d2c4db4109291fb0e4f312108aeabda02103915f3155498fe2d96b43bfb4fe62e0839ab485e14c0f9cc88626c74301014f5842f454394c050147f386ecda2472fee340b011e4412be858a2e842a32d84b360305e18ac2bc9623d90b4148adf8c08ef599088837023d2d5e444dc7ae025d05d2187d3c1fa5319ee8d9a4b925fcb7f48bff2c86ab3cc8e0d86b4db052511251f00b73077e5f7b8176940b6da187b00c6d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148653);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/14");

  script_cve_id("CVE-2021-0273");
  script_xref(name:"JSA", value:"JSA11164");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11164)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11164
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11164");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11164");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0273");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(ACX58[0-9]{2}|EX92[0-9]{2}|MX1[0-9]{4}|MX240|MX480|MX960)([^0-9]|$)" || model =~ "^MX10001([^0-9]|$)")
  audit(AUDIT_DEVICE_NOT_VULN, model);

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.1',   'fixed_ver':'17.1R2-S12'},
  {'min_ver':'17.2',   'fixed_ver':'17.2R3-S4'},
  {'min_ver':'17.3',   'fixed_ver':'17.3R3-S8'},
  {'min_ver':'17.4',   'fixed_ver':'17.4R2-S10'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S2'},
  {'min_ver':'18.1',   'fixed_ver':'18.1R3-S10'},
  {'min_ver':'18.2',   'fixed_ver':'18.2R2-S7'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S3'},
  {'min_ver':'18.3',   'fixed_ver':'18.3R1-S7'},
  {'min_ver':'18.3R2', 'fixed_ver':'18.3R3-S2'},
  {'min_ver':'18.4',   'fixed_ver':'18.4R1-S7'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S4'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S2'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R1-S5'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S1', 'fixed_display':'19.1R2-S1, 19.1R3'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R1-S4', 'fixed_display':'19.2R1-S4, 19.2R2'},
  {'min_ver':'19.3',   'fixed_ver':'19.3R2-S3', 'fixed_display':'19.3R2-S3, 19.3R3'},
  {'min_ver':'19.4',   'fixed_ver':'19.4R1-S1', 'fixed_display':'19.4R1-S1, 19.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var vuln_cards = make_list(
  'MX-MPC3E-3D',
  'MPC4E-3D-32XGE',
  'MPC4E-3D-2CGE-8XGE',
  'EX9200-32XS',
  'EX9200-2C-8XS',
  'FPC5-3D',
  'FPC5-LSR',
  'EX9200-4QS'
);

var override = TRUE;

var buf = junos_command_kb_item(cmd:'show chassis hardware models');
var vuln = FALSE;
if (junos_check_result(buf))
{
  override = FALSE;

  foreach var vuln_card (vuln_cards)
  {
    if (vuln_card >< buf)
    {
      vuln = TRUE;
      break;
    }
  }
  if(!vuln)
    audit(AUDIT_HOST_NOT, 'using an affected Trio line card');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
