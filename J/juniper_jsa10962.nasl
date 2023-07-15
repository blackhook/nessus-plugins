#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130053);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-0063");
  script_xref(name:"JSA", value:"JSA10962");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Juniper JSA10962");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 15.1R7-S5, 16.1R7-S5, 16.2R2-S10, 17.1R3-S1, 17.2R3-S2,
17.3R3-S6, 17.4R2-S5, 18.1R3-S6, 18.2R2-S4, 18.2X75-D50, 18.3R1-S5, 18.4R2, or 19.1R1-S2. It is, therefore, affected by
a vulnerability as referenced in the JSA10962 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10962");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10962");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0063");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (model =~ "^MX")
{
  fixes["15.1"] = "15.1R7-S5";
  fixes["16.1"] = "16.1R7-S5";
  fixes["16.2"] = "16.2R2-S10";
  fixes["17.1"] = "17.1R3-S1";
  fixes["17.2"] = "17.2R3-S2";
  fixes["17.3"] = "17.3R3-S6";
  fixes["17.4"] = "17.4R2-S5";
  fixes["18.1"] = "18.1R3-S6";
  fixes["18.2"] = "18.2R2-S4";
  fixes["18.2X75"] = "18.2X75-D50";
  fixes["18.3"] = "18.3R1-S5";
  fixes["18.4"] = "18.4R2";
  fixes["19.1"] = "19.1R1-S2";
}
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
