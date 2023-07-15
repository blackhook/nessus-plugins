#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126925);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2018-0045");

  script_name(english:"Juniper JSA10879");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of the tested product installed on the remote host is 
prior to the fixed version in the advisory. It is, therefore, affected
by a denial of service vulnerability that exists in RPD daemon. An 
unauthenticated, remote attacker can exploit this issue, by continuously
sending a specific Draft-Rosen MVPN control packet, to repeatedly crash
the RPD process causing a prolonged denial of service as referenced in
the JSA10879 advisory. 
Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10879");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10879");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/23");

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

if (model =~ '^SRX')
  fixes['12.1X46'] = '12.1X46-D77';
  fixes['12.3X48'] = '12.3X48-D70';
  fixes['15.1X49'] = '15.1X49-D140';

if (model =~ '^EX2300' || model =~ '^EX3400' )
  fixes['15.1X53'] = '15.1X53-D59';

if (model =~ '^QFX10K')
  fixes['15.1X53'] = '15.1X53-D67';

if (model =~ '^QFX5200' || model =~ '^QFX5110' )
  fixes['15.1X53'] = '15.1X53-D233';

if (model =~ '^NFX')
  fixes['15.1X53'] = '15.1X53-D471';
  
fixes['12.3'] = '12.3R12-S10';
fixes['15.1'] = '15.1R4-S9';
fixes['16.1'] = '16.1R4-S9';
fixes['16.2'] = '16.2R1-S6';
fixes['17.1'] = '17.1R1-S7';
fixes['17.2'] = '17.2R2-S4';
fixes['17.3'] = '17.3R2-S2';
fixes['17.4'] = '17.4R1-S3';
fixes['18.1'] = '18.1R2';

if (ver == '15.1F6')
    fix = 'No fixed version avaliable, check the vendor website for more info.';
else
    fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
