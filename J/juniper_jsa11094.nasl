##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146194);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2021-0222");
  script_xref(name:"JSA", value:"JSA11094");

  script_name(english:"Juniper Junos OS DoS (JSA11094)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced
in the JSA11094 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11094");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11094");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

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

model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX2300|EX3400|EX4300|EX4600|EX4650|QFX3500|QFX5100|QFX5110|QFX5120|QFX5200|QFX5210)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
];
if (model =~ '^(EX4300|EX4600|QFX3500|QFX5100)')
{
  append_element(var:vuln_ranges, value:{'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D53'});
  append_element(var:vuln_ranges, value:{'min_ver':'15.1', 'fixed_ver':'15.1R7-S6'});
}
if (model =~ '^(EX4300|EX4600|QFX5100)')
{
  append_element(var:vuln_ranges, value:{'min_ver':'16.1', 'fixed_ver':'16.1R7-S7'});
  append_element(var:vuln_ranges, value:{'min_ver':'17.1', 'fixed_ver':'17.1R2-S11'});
}
if (model =~ '^EX4300')
{
  append_element(var:vuln_ranges, value:{'min_ver':'17.1R3', 'fixed_ver':'17.1R3-S2'});
  append_element(var:vuln_ranges, value:{'min_ver':'17.2', 'fixed_ver':'17.2R1-S9'});
  append_element(var:vuln_ranges, value:{'min_ver':'18.3R2', 'fixed_ver':'18.3R2-S3'});
  append_element(var:vuln_ranges, value:{'min_ver':'19.2', 'fixed_ver':'19.2R1-S4', 'fixed_display':'19.2R1-S4, 19.2R2'});
  append_element(var:vuln_ranges, value:{'min_ver':'19.3', 'fixed_ver':'19.3R2-S1'});
}
if (model =~ '^(EX4300|EX4600|QFX5100|QFX5110|QFX5200)')
{
  append_element(var:vuln_ranges, value:{'min_ver':'17.2R2', 'fixed_ver':'17.2R3-S3'});
  append_element(var:vuln_ranges, value:{'min_ver':'17.3', 'fixed_ver':'17.3R2-S5'});
  append_element(var:vuln_ranges, value:{'min_ver':'17.3R3', 'fixed_ver':'17.3R3-S7'});
  append_element(var:vuln_ranges, value:{'min_ver':'17.4', 'fixed_ver':'17.4R2-S9', 'fixed_display':'17.4R2-S9, 17.4R3'});
}
if (model =~ '^(EX2300|EX3400|EX4300|EX4600|QFX5100|QFX5110|QFX5200|QFX5210)')
{
  append_element(var:vuln_ranges, value:{'min_ver':'18.1', 'fixed_ver':'18.1R3-S9'});
  if (model =~'EX4300')
  {
    append_element(var:vuln_ranges, value:{'min_ver':'18.2', 'fixed_ver':'18.2R2-S7'});
    append_element(var:vuln_ranges, value:{'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S3'});
  }
  else
    append_element(var:vuln_ranges, value:{'min_ver':'18.2', 'fixed_ver':'18.2R3-S3'});
}
if (model =~ '^(EX2300|EX3400|EX4300|EX4600|EX4650|QFX5100|QFX5110|QFX5120|QFX5200|QFX5210)')
{
  append_element(var:vuln_ranges, value:{'min_ver':'18.3', 'fixed_ver':'18.3R1-S7'});
  append_element(var:vuln_ranges, value:{'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S1'});
  append_element(var:vuln_ranges, value:{'min_ver':'18.4', 'fixed_ver':'18.4R1-S5'});
  append_element(var:vuln_ranges, value:{'min_ver':'19.1', 'fixed_ver':'19.1R1-S4'});
  append_element(var:vuln_ranges, value:{'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S1', 'fixed_display':'19.1R2-S1, 19.1R3'});
}
if (model =~ '^(EX2300|EX3400|EX4600|EX4650|QFX5100|QFX5110|QFX5120|QFX5200|QFX5210)')
{
  append_element(var:vuln_ranges, value:{'min_ver':'19.2', 'fixed_ver':'19.2R1-S3', 'fixed_display':'19.2R1-S3, 19.2R2'});
  append_element(var:vuln_ranges, value:{'min_ver':'19.3', 'fixed_ver':'19.3R1-S1', 'fixed_display':'19.3R1-S1, 19.3R2, 19.3R3'});
}

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
