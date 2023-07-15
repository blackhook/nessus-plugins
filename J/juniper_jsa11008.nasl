#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138210);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1628");
  script_xref(name:"JSA", value:"JSA11008");

  script_name(english:"Juniper Junos Information Exposure Vulnerability (JSA11008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 14.1X53-D53, 15.1R7-S6, 15.1X49-D200, 16.1R7-S7,
17.1R2-S11, 17.2R3-S3, 17.3R2-S5, 17.4R2-S9, 18.1R3-S8, 18.2R3-S2, 18.3R2-S3, 18.4R1-S5, 19.1R1-S4, 19.2R1-S4, or
19.3R1-S1. It is, therefore, affected by an information exposure vulnerability as referenced in the JSA11008 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1628");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11008");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11008");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1628");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/08");

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
fixes = make_array();

if (model =~ "^EX4300")
{
  fixes['14.1X53'] = '14.1X53-D53';
  fixes['15.1'] = '15.1R7-S6';
  fixes['15.1X49'] = '15.1X49-D200';
  fixes['16.1'] = '16.1R7-S7';
  fixes['17.1'] = '17.1R2-S11';
  fixes['17.2'] = '17.2R3-S3';
  fixes['17.3'] = '17.3R2-S5';
  fixes['17.4'] = '17.4R2-S9';
  fixes['18.1'] = '18.1R3-S8';
  fixes['18.2'] = '18.2R3-S2';
  fixes['18.3'] = '18.3R2-S3';
  fixes['18.4'] = '18.4R1-S5';
  fixes['19.1'] = '19.1R1-S4';
  fixes['19.2'] = '19.2R1-S4';
  fixes['19.3'] = '19.3R1-S1';
}
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
