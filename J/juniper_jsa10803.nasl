#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102078);
  script_version ("1.6");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2017-10602");
  script_xref(name:"JSA", value:"JSA10803");

  script_name(english:"Juniper Junos CLI Local Privilege Escalation (JSA10803)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a local privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by an unspecified buffer overflow condition
in the CLI component that allows a local attacker who has read-only
privileges to execute arbitrary code with root privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10803");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10803.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10602");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();

# 14.1X53 versions prior to 14.1X53-D46 on EX2200/VC, EX3200,
# EX3300/VC, EX4200, EX4300, EX4550/VC, EX4600, EX6200,
# EX8200/VC (XRE), QFX3500, QFX3600, QFX5100;
if (model =~ "EX2200\/VC" ||
    model =~ "EX3200" ||
    model =~ "EX3300\/VC" ||
    model =~ "EX4200" ||
    model =~ "EX4300" ||
    model =~ "EX4550\/VC" ||
    model =~ "EX4600" ||
    model =~ "EX6200" ||
    model =~ "EX8200\/VC \(XRE\)" ||
    model =~ "QFX3500" ||
    model =~ "QFX3600" ||
    model =~ "QFX5100")
{
  fixes['14.1X53'] = '14.1X53-D46';
}

fixes['14.2']    = '14.2R6';
fixes['15.1']    = '15.1R3';
fixes['15.1X49'] = '15.1X49-D40';
fixes['15.1X53'] = '15.1X53-D47';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, severity:SECURITY_HOLE);
