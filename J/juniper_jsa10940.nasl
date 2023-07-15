#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130514);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2015-6564",
    "CVE-2015-8325",
    "CVE-2016-6210",
    "CVE-2016-6515",
    "CVE-2016-10009",
    "CVE-2016-10010",
    "CVE-2016-10011",
    "CVE-2016-10012"
  );
  script_bugtraq_id(
    76317,
    86187,
    91812,
    92212,
    94968,
    94972,
    94975
  );
  script_xref(name:"JSA", value:"JSA10940");

  script_name(english:"Juniper JSA10940");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 12.3X48-D55, 12.3R12-S13, 15.1X49-D100, 15.1F6-S12,
16.1R3-S4, 16.2R1-S4, 17.1R1-S2, or 17.2R1. It is, therefore, affected by a vulnerability as referenced in the JSA10940
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10940");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10940");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10009");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-10012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.3X48'] = '12.3X48-D55';
fixes['12.3'] = '12.3R12-S13';
fixes['15.1X49'] = '15.1X49-D100';
fixes['15.1F'] = '15.1F6-S12';
fixes['16.1'] = '16.1R3-S4';
fixes['16.2'] = '16.2R1-S4';
fixes['17.1'] = '17.1R1-S2';
fixes['17.2'] = '17.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
