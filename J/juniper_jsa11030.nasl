#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138605);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1643");
  script_xref(name:"JSA", value:"JSA11030");
  script_xref(name:"IAVA", value:"2020-A-0320-S");

  script_name(english:"Juniper Junos Denial of Service (DoS) JSA11030");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device it is affected by a Denial of Service (DoS)
vulnerability. By continuously executing the same CLI commands 'show ospf interface extensive' or 'show ospf interface
detail' CLI commands, a local attacker can repeatedly crash the RPD process causing a sustained Denial of Service.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11030");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11030");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include("hostlevel_funcs.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

# Only systems utilizing ARM processors, found on the EX2300 and EX3400, are vulnerable to this issue.
uname = get_kb_item_or_exit("Host/uname");
if("arm" >!< tolower(uname) || (model !~ '^EX(23|34)00'))
  audit(AUDIT_HOST_NOT, "affected");

fixes['12.3X48'] = '12.3X48-D100';
fixes['14.1X53'] = '14.1X53-D54';
fixes['15.1'] = '15.1R7-S7';
fixes['15.1X49'] = '15.1X49-D210';
fixes['15.1X53'] = '15.1X53-D593';
fixes['16.1'] = '16.1R7-S8';
fixes['17.1'] = '17.1R2-S12';
fixes['17.2'] = '17.2R3-S4';
fixes['17.3'] = '17.3R3-S8';
fixes['17.4'] = '17.4R2-S2';
fixes['18.1'] = '18.1R3-S2';
fixes['18.2'] = '18.2R2';
fixes['18.2X75'] = '18.2X75-D40';
fixes['18.3'] = '18.3R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);