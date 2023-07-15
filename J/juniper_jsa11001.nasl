##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146092);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2020-1618");
  script_xref(name:"JSA", value:"JSA11001");

  script_name(english:"Juniper Junos Authentication Bypass (JSA11001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 14.1X53-D53, 15.1R7-S4, 15.1X53-D593, 16.1R7-S4,
17.1R2-S11, 17.2R3-S3, 17.3R2-S5, 17.4R2-S9, 18.1R3-S8, 18.2R2, or 18.3R1-S7. It is, therefore, affected by an 
authentication bypass vulnerability as referenced in the JSA11001 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11001");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11001");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1618");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^(EX|QFX)")
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

vuln_ranges = [
  {'min_ver':'14.1X53',   'fixed_ver':'14.1X53-D53'},
  {'min_ver':'15.1',      'fixed_ver':'15.1R7-S4'},
  {'min_ver':'15.1X53',   'fixed_ver':'15.1X53-D593'},
  {'min_ver':'16.1',      'fixed_ver':'16.1R7-S4'},
  {'min_ver':'17.1',      'fixed_ver':'17.1R2-S11'},
  {'min_ver':'17.1R3',    'fixed_ver':'17.1R3-S1'},
  {'min_ver':'17.2',      'fixed_ver':'17.2R3-S3'},
  {'min_ver':'17.3',      'fixed_ver':'17.3R2-S5'},
  {'min_ver':'17.3R3',    'fixed_ver':'17.3R3-S6'},
  {'min_ver':'17.4',      'fixed_ver':'17.4R2-S9', 'fixed_display':'17.4R2-S9 / 17.4R3'},
  {'min_ver':'18.1',      'fixed_ver':'18.1R3-S8'},
  {'min_ver':'18.2',      'fixed_ver':'18.2R2'},
  {'min_ver':'18.3',      'fixed_ver':'18.3R1-S7', 'fixed_display':'18.3R1-S7 / 18.3R2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
report = get_report(ver:ver, model:model, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
