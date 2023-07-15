#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124765);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id("CVE-2019-0040");
  script_bugtraq_id(107902);
  script_xref(name:"JSA", value:"JSA10929");

  script_name(english:"Juniper JSA10929");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a vulnerability as
referenced in the JSA10929 advisory. Note that Nessus has not tested
for this issue but has instead relied only on the application's self-
reported version number.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10929
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?714b38f7");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16613");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16765");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/KB16446");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10929");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0040");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes["15.1"] = "15.1F6-S12";
fixes["15.1X53"] = "15.1X53-D236";
fixes["16.1"] = "16.1R7-S1";
fixes["16.2"] = "16.2R2-S9";
fixes["17.1"] = "17.1R3";
fixes["17.2"] = "17.2R1-S8";
fixes["17.3"] = "17.3R2";
fixes["17.4"] = "17.4R1-S1";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
