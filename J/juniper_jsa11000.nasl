#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136701);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1617");
  script_xref(name:"JSA", value:"JSA11000");

  script_name(english:"Juniper JSA11000");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 17.4R2-S9, 18.1R3-S9, 18.2X75-D12, 18.2R3, or 18.3R3.
It is, therefore, affected by a vulnerability as referenced in the JSA11000 advisory. Note that Nessus has not tested
for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11000");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11000");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/19");

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

if (model !~ "^(PTX1|QFX1)")
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes["17.4"]     = "17.4R2-S9";
fixes["18.1"]     = "18.1R3-S9";
fixes["18.2X75"]  = "18.2X75-D12";
fixes["18.2"]     = "18.2R3";
fixes["18.3"]     = "18.3R3";

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
