#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139071);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1637");
  script_xref(name:"JSA", value:"JSA11018");

  script_name(english:"Junos OS: SRX Series: Unified Access Control (UAC) bypass vulnerability (JSA11018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 12.3X48-D100, 15.1X49-D210, 17.3R2-S5, 17.4R2-S9,
18.1R3-S10, 18.2R2-S7, 18.3R1-S7, 18.4R1-S6, 19.1R1-S4, 19.2R1-S3, 19.3R2-S1, or 19.4R1-S1. It is, therefore, affected
by a unified access control (UAC) bypass vulnerability as referenced in the JSA11018 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11018");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11018");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^SRX[0-9]+") 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();

fixes['12.3X48'] = '12.3X48-D100';
fixes['15.1X49'] = '15.1X49-D210';
fixes['17.3'] = '17.3R2-S5';
fixes['17.4'] = '17.4R2-S9';
fixes['18.1'] = '18.1R3-S10';
fixes['18.2'] = '18.2R2-S7';
fixes['18.3'] = '18.3R1-S7';
fixes['18.4'] = '18.4R1-S6';
fixes['19.1'] = '19.1R1-S4';
fixes['19.2'] = '19.2R1-S3';
fixes['19.3'] = '19.3R2-S1';
fixes['19.4'] = '19.4R1-S1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
