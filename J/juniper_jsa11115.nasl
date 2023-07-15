##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148664);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2019-8936");
  script_xref(name:"JSA", value:"2014-07 Security Bulletin");
  script_xref(name:"JSA", value:"2017-05 Out of Cycle Security Bulletin");
  script_xref(name:"JSA", value:"2018-10 Security Bulletin");
  script_xref(name:"JSA", value:"2015-10 Out of Cycle Security Bulletin");
  script_xref(name:"JSA", value:"2017-04 Security Bulletin");
  script_xref(name:"JSA", value:"2021-04 Security Bulletin");
  script_xref(name:"JSA", value:"JSA11115");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11115)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11115
advisory.

  - NTP through 4.2.8p12 has a NULL Pointer Dereference. (CVE-2019-8936)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10613");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10663");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10898");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10711");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10776");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11171");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11115");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11115");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8936");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/01");
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

model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX|EX23|EX34|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S6'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R7-S7'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S11'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S11'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R1-S9'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S5'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S9'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S9'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S6'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S7'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S5'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S4'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R1-S1'}
];
if (model =~ '^EX')
{
  append_element(var:vuln_ranges, value:{'min_ver':'12.3', 'fixed_ver':'12.3R12-S15'});
  append_element(var:vuln_ranges, value:{'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D140'});
}
if (model =~ '^SRX')
{
  append_element(var:vuln_ranges, value:{'min_ver':'12.3X48', 'fixed_ver':'12.3X48-D95'});
  append_element(var:vuln_ranges, value:{'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D200'});
}
if (model =~ '^(EX23|EX34)')
{
  append_element(var:vuln_ranges, value:{'min_ver':'15.1X53', 'fixed_ver':'15.1X53-D593'});
}

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
