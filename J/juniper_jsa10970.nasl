#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133303);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-0047",
    "CVE-2019-0050",
    "CVE-2019-0054",
    "CVE-2019-0055",
    "CVE-2019-0057",
    "CVE-2019-0058",
    "CVE-2019-0059",
    "CVE-2019-0060",
    "CVE-2019-0062",
    "CVE-2019-0063",
    "CVE-2019-0064",
    "CVE-2019-0066",
    "CVE-2019-0067",
    "CVE-2019-0068",
    "CVE-2019-0073",
    "CVE-2019-0075"
  );
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Juniper JSA10970");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a vulnerability as
referenced in the JSA10970 advisory. Note that Nessus has not tested
for this issue but has instead relied only on the application's self-
reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16613");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16765");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16446");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10970");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10970");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0058");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-0062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D86';
fixes['12.3'] = '12.3R12-S13';
fixes['12.3X48'] = '12.3X48-D80';
fixes['14.1X53'] = '14.1X53-D51';

if (ver =~ "^15\.1F")
fixes['15.1F'] = '15.1F6-S13';
else
  fixes['15.1'] = '15.1R7-S4';

fixes['15.1X49'] = '15.1X49-D171';
fixes['15.1X53'] = '15.1X53-D69';
fixes['16.1'] = '16.1R7-S5';
fixes['16.2'] = '16.2R2-S9';
fixes['17.1'] = '17.1R3';

if (ver =~ "^17\.2R1")
  fixes['17.2'] = '17.2R1-S8';
else if (ver =~ "^17\.2R2")
  fixes['17.2'] = '17.2R2-S7';
else if (ver =~ "^17\.2R3")
  fixes['17.2'] = '17.2R3-S1';

fixes['17.3'] = '17.3R3-S6';

if (ver =~ "^17\.4R1")
  fixes['17.4'] = '17.4R1-S7';
else if (ver =~ "^17\.4R2")
  fixes['17.4'] = '17.4R2-S4';
else
  fixes['17.4'] = '17.4R3';

fixes['18.1'] = '18.1R3-S5';

if (ver =~ "^18\.2R1")
  fixes['18.2'] = '18.2R1-S5';
else if (ver =~ "^18\.2R2")
  fixes['18.2'] = '18.2R2-S3';
else
  fixes['18.2'] = '18.2R3';

if (ver =~ "^18\.3R1")
  fixes['18.3'] = '18.3R1-S3';
else if (ver =~ "^18\.3R2")
  fixes['18.3'] = '18.3R2';
else if (ver =~ "^18\.3R3")
  fixes['18.3'] = '18.3R3';

if (ver =~ "^18\.4R1")
  fixes['18.4'] = '18.4R1-S2';
else
  fixes['18.4'] = '18.4R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
