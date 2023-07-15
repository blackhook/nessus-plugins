#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130518);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0068");
  script_xref(name:"JSA", value:"JSA10968");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: Multicast flowd DoS (JSA10968)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a vulnerability in the
flowd process. An unauthenticated, remote attacker can exploit this issue, by repeatedly sending specific multicast
packets to an affected device, to cause the device to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10968");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10968.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

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
# Only SRX Series platforms are affected
if ( 'SRX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

# All 17.3 versions are vulnerable;
# Passing 17.4R2-S5 as fix fails to flag 17.3RX versions as _junos_base_ver_compare()
# won't compare different major versions.
if (ver =~ "^17.3($|[^0-9])")
  vuln_major_version = TRUE;

fixes = make_array();

fixes['12.3X48'] = '12.3X48-D90';
fixes['15.1X49'] = '15.1X49-D180';
fixes['17.4'] = '17.4R2-S5';
fixes['18.1'] = '18.1R3-S6';
fixes['18.2'] = '18.2R2-S4';
fixes['18.3'] = '18.3R2-S1';
fixes['18.4'] = '18.4R2';
fixes['19.1'] = '19.1R1-S1';

if (vuln_major_version)
  fix = 'Upgrade to 17.4R2-S5 or later.';
else
  fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

report = get_report(model:model, ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
