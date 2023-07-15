#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133965);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id(
    "CVE-2020-1600",
    "CVE-2020-1601",
    "CVE-2020-1602",
    "CVE-2020-1603",
    "CVE-2020-1604",
    "CVE-2020-1605",
    "CVE-2020-1607",
    "CVE-2020-1608",
    "CVE-2020-1609"
  );
  script_xref(name:"IAVA", value:"2020-A-0012-S");

  script_name(english:"Juniper JSA10979");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a vulnerability as
referenced in the JSA10979 advisory. Note that Nessus has not tested
for this issue but has instead relied only on the application's self-
reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16613");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16765");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16446");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10979");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10979");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixes["12.3X48"] = "12.3X48-D90";
fixes["15.1"] = "15.1R7-S6";
fixes["15.1X49"] = "15.1X49-D200";
fixes["15.1X53"] = "15.1X53-D238";
fixes["16.1"] = "16.1R7-S5";
fixes["16.2"] = "16.2R2-S11";
fixes["17.1"] = "17.1R3-S1";
fixes["17.2"] = "17.2R3-S2";
fixes["17.3"] = "17.3R3-S7";
fixes["17.4"] = "17.4R2-S4";
fixes["18.1"] = "18.1R3-S5";
fixes["18.2"] = "18.2R3";
fixes["18.2X75"] = "18.2X75-D50";
fixes["18.3"] = "18.3R2";
fixes["18.4"] = "18.4R1-S6";
fixes["19.1"] = "19.1R2";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

report = get_report(ver:ver, fix:fix);

security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
