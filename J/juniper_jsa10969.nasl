#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130459);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0069");
  script_xref(name:"JSA", value:"JSA10969");
  script_xref(name:"IAVA", value:"2019-A-0404");

  script_name(english:"Junos OS: Clear Text Authentication Credentials (JSA10969)");
  script_summary(english:"Checks the Junos version and juniper's model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability which is when the user
uses console management port to authenticate, the credentials used
during device authentication are written to a log file in clear text.
This issue does not affect users that are logging-in using telnet,
SSH or J-web to the management IP as referenced in the JSA10969 advisory.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10969");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10969.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0069");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (model =~ '^vSRX' || model =~ '^SRX15' || model =~ '^SRX40')
{
    fixes['15.1X49'] = '15.1X49-D110';
}

if (model =~ '^QFX10K')
{
    fixes['15.1X53'] = '15.1X53-D68';
}

if (model =~ '^QFX511' || model =~ '^QFX520')
{
    fixes['15.1X53'] = '15.1X53-D234';
}

if (model =~ '^QFX511' || model =~ '^QFX520' || model =~ '^QFX10K')
{
    fixes['17.1'] = '17.1R2-S8';
    fixes['17.2'] = '17.2R1-S7';
}

if (model =~ '^vSRX' || model =~ '^SRX15' || model =~ '^SRX40' || model =~ '^QFX511' || model =~ '^QFX520' || model =~ '^QFX10K')
{
    fixes['17.3'] = '17.3R2';
}

if (model =~ '^ACX5' || model =~ '^EX46' || model =~ '^QFX510')
{
    fixes['14.1X53'] = '14.1X53-D47';
    fixes['15.1'] = '15.1R7';
    fixes['16.1'] = '16.1R7';
    fixes['17.1'] = '17.1R2-S10';
    fixes['17.2'] = '17.2R3';
    fixes['17.3'] = '17.3R3';
    fixes['17.4'] = '17.4R2';
    fixes['18.1'] = '18.1R2';
}

if (model =~ '^NFX')
{
    fixes['15.1X53'] = '15.1X53-D496';
    fixes['17.2'] = '17.2R3-S1';
    fixes['17.3'] = '17.3R3-S4';
    fixes['17.4'] = '17.4R2-S4';
    fixes['18.1'] = '18.1R3-S4';
    fixes['18.2'] = '18.2R2-S3';
    fixes['18.3'] = '18.3R1-S3';
    fixes['18.4'] = '18.4R1-S1';
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);