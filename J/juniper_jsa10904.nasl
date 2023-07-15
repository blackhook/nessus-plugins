#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125546);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2015-1283");

  script_name(english:"Juniper JSA10904");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is 12.3 prior
to 12.3R12-S12, 12.3X48 prior to 12.3X48-D76, 14.1X53 prior to 14.1X53-D48,
15.1 prior to 15.1R5, 15.1X49 prior to 15.1X49-D151, 15.1 prior to 15.1F6-S12
or 16.1 prior to 16.1R2. It is, therefore, affected by a denial of service 
(DoS) vulnerability. An unauthenticated, remote attacker can exploit this 
issue, via a crafted XML data input, to cause the system to stop responding
and potentially with other possible unspecified impacts as referenced in the
JSA10904 advisory. 
Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10904");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10904");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixes["12.3"] = "12.3R12-S12";
fixes["15.1"] = "15.1R5";
fixes["15.1F"] = "15.1F6-S12";
fixes["16.1"] = "16.1R2";

if (model =~ "^SRX")
{
  fixes["12.3X48"] = "12.3X48-D76";
  fixes["15.1X49"] = "15.1X49-D151";
}

if (model =~ "^(EX2200|EX3200|EX3300|EX4200|EX4300|EX4550|EX4600|EX6200|EX8200/VC \(XRE\)|QFX3500|QFX3600|QFX5100)")
  fixes["14.1X53"] = "14.1X53-D48";

if (model =~ '^(EX2300|EX3400)')
  fixes['15.1X53'] = '15.1X53-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
