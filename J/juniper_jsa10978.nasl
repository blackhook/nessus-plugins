#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140737);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2019-0071");
  script_xref(name:"JSA", value:"JSA10978");

  script_name(english:"Juniper Junos Privilege Escalation (JSA10978)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is EX2300, EX2300-C or EX3400 version 18.1R3-S4
or 18.3R1-S3. It is, therefore, affected by a privilege escalation vulnerability as referenced in the 
JSA10978 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10978");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10978");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0071");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (model =~ "^EX(23\d{2}(-C)?|34\d{2})$")
{
    if (ver == '18.1R3-S4')
        fixes['18.1'] = '18.1R3-S5';
    else if (ver == '18.3R1-S3')
        fixes['18.3'] = '18.3R1-S4';
    
}
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);

