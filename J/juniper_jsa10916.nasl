#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121070);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2016-3627",
    "CVE-2016-3705",
    "CVE-2016-4447",
    "CVE-2016-4448",
    "CVE-2016-4449",
    "CVE-2017-7375",
    "CVE-2017-18258",
    "CVE-2018-9251"
  );
  script_xref(name:"JSA", value:"JSA10916");

  script_name(english:"Junos OS: Multiple vulnerabilities in libxml2 (JSA10916)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a Multiple vulnerabilities in libxml2:

- Format string vulnerability in libxml2 before 2.9.4 allows 
  attackers to have unspecified impact via format string 
  specifiers in unknown vectors.(CVE-2016-4448)
  
- The xmlStringGetNodeList function in tree.c in libxml2 2.9.3 and 
  earlier, when used in recovery mode, allows context-dependent 
  attackers to cause a denial of service (infinite recursion, stack 
  consumption, and application crash) via a crafted XML document. 
  (CVE-2016-3627)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10916");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10916.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4448");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

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

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();

fixes['12.3R'] = '12.3R12-S10';

if (model =~ '^SRX')
{
    fixes['12.1X46'] = '12.1X46-D81';
    fixes['12.3X48'] = '12.3X48-D75';
    fixes['15.1X49'] = '15.1X49-D150';
}
if (model =~ '^NFX')
{
    fixes['15.1X53'] = '15.1X53-D495';
}
if (model =~ '^QFX5')
{
    fixes['15.1X53'] = '15.1X53-D234';
}
if (model =~ '^QFX10000')
{
    fixes['15.1X53'] = '15.1X53-D68';
}
if (model =~ '^EX')
{
    fixes['15.1X53'] = '15.1X53-D590';
}
if (model =~ '^EX' || model =~ '^QFX')
{
    fixes['14.1X53'] = '15.1X53-D590';
}
fixes['15.1'] = '15.1R4-S9';
fixes['15.1F'] = '15.1F6-S11';
fixes['16.1'] = '16.1R4-S11';
fixes['16.2'] = '16.2R2-S7';
fixes['17.1'] = '17.1R2-S9';
fixes['17.2'] = '17.2R1-S7';
fixes['17.3'] = '17.3R2-S4';
fixes['17.4'] = '17.4R2';
fixes['18.1'] = '18.1R2-S2';
fixes['18.2'] = '18.2R1-S1';
fixes['18.2X75'] = '18.2X75-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix);
  security_hole(port:0, extra:report);
}
else security_hole(0);
