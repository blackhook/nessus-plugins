#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125773);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2018-0055");

  script_name(english:"Juniper JSA10889");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to
tested version. It is, therefore, affected by a denial of service
vulnerability in the Junos OS device configured as a DHCP server in a 
Broadband Edge (BBE) environment. A remote attacker can exploit it via 
sending a continuous, specially crafted DHCPv6 message which can result 
in a repeatedly jdhcpd daemon crash which lead to a denial of service 
condition as referenced in the JSA10889 advisory.
Note that Nessus has not tested for this issue but has instead relied only
 on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10889");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10889");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0055");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");

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

fixes["15.1"] = "15.1R7-S2";
fixes["15.1X49"] = "15.1X49-D160";
fixes["15.1X53"] = "15.1X53-D235";
fixes["16.1"] = "16.1R4-S11";
fixes["16.2"] = "16.2R2-S7";
fixes["17.1"] = "17.1R2-S9";
fixes["17.2"] = "17.2R2-S6";
fixes["17.3"] = "17.3R3-S1";
fixes["17.4"] = "17.4R1-S5";
fixes["18.1"] = "18.1R2-S3";
fixes["18.2"] = "18.2R1-S2";
fixes["18.2X75"] = "18.2X75-D20";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
