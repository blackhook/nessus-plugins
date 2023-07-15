#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165723);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-31382");
  script_xref(name:"JSA", value:"JSA11250");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Race Condition (JSA11250)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11250
advisory. On PTX1000 System, PTX10002-60C System, after upgrading to an affected release, a Race Condition 
vulnerability between the chassis daemon (chassisd) and firewall process (dfwd) of Juniper Networks Junos OS, may 
update the device's interfaces with incorrect firewall filters. This issue only occurs when upgrading the device to an
affected version of Junos OS. Interfaces intended to have protections may have no protections assigned to them. 
Interfaces with one type of protection pattern may have alternate protections assigned to them. Interfaces intended to
have no protections may have protections assigned to them. These firewall rule misassignments may allow genuine traffic
intended to be stopped at the interface to propagate further, potentially causing disruptions in services by 
propagating unwanted traffic. An attacker may be able to take advantage of these misassignments. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11250");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11250");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31382");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ '^PTX1000$|^PTX10002-60C')
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges;
if (model =~ '^PTX1000$')
{
  vuln_ranges = [
    {'min_ver':'17.2R1', 'fixed_ver':'17.3R3-S12', 'model':"^PTX1000($|-)"},
    {'min_ver':'17.4', 'fixed_ver':'17.4R3-S5', 'model':"^PTX1000($|-)"},
    {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13', 'model':"^PTX1000($|-)"},
    {'min_ver':'18.2R1', 'fixed_ver':'18.2R3-S8', 'model':"^PTX1000($|-)"},
    {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5', 'model':"^PTX1000($|-)"},
    {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8', 'model':"^PTX1000($|-)"},
    {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S8', 'model':"^PTX1000($|-)"},
    {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S8', 'model':"^PTX1000($|-)"},
    {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5', 'model':"^PTX1000($|-)"},
    {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2', 'model':"^PTX1000($|-)"},
    {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6', 'model':"^PTX1000($|-)"},
    {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S3', 'model':"^PTX1000($|-)"},
    {'min_ver':'19.4', 'fixed_ver':'19.4R2-S4', 'model':"^PTX1000($|-)"},
    {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S3', 'model':"^PTX1000($|-)"},
    {'min_ver':'20.1', 'fixed_ver':'20.1R3', 'model':"^PTX1000($|-)"},
    {'min_ver':'20.2', 'fixed_ver':'20.2R2-S3', 'model':"^PTX1000($|-)", 'fixed_display':'20.2R2-S3, 20.2R3'},
    {'min_ver':'20.3', 'fixed_ver':'20.3R2-S1', 'model':"^PTX1000($|-)", 'fixed_display':'20.3R2-S1, 20.3R3'},  
    {'min_ver':'20.4', 'fixed_ver':'20.4R1-S1', 'model':"^PTX1000($|-)", 'fixed_display':'20.4R1-S1, 20.4R2'}
  ];
}
else if (model =~ '^PTX10002-60C')
{
  vuln_ranges = [
    {'min_ver':'18.2R1', 'fixed_ver':'18.4R3-S9', 'model':"^PTX10002-60C"},
    {'min_ver':'19.1R1', 'fixed_ver':'19.4R2-S5', 'model':"^PTX10002-60C"},
    {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S5', 'model':"^PTX10002-60C"},
    {'min_ver':'20.1', 'fixed_ver':'20.1R3-S1', 'model':"^PTX10002-60C"},
    {'min_ver':'20.2', 'fixed_ver':'20.2R2-S2', 'model':"^PTX10002-60C"},
    {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1', 'model':"^PTX10002-60C"},
    {'min_ver':'20.4R1', 'fixed_ver':'21.1R2', 'model':"^PTX10002-60C"},
    {'min_ver':'21.2R1', 'fixed_ver':'21.3R2', 'model':"^PTX10002-60C"}
  ];
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
{
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
}
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);