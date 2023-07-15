#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133145);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2020-1608");
  script_xref(name:"JSA", value:"JSA10987");
  script_xref(name:"IAVA", value:"2020-A-0012-S");

  script_name(english:"Junos OS: Broadband Edge Service Denial of Service (DoS) Vulnerability (JSA10987)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service
vulnerability due to an unspecified issue in the processing of packets destined to Broadband Edge (BBE) clients
connected to MX Series subscriber management platforms. Receipt of a specific MPLS or IPv6 packet on the core facing 
interface of an MX Series device configured for BBE service may trigger a kernel crash (vmcore). An unauthenticated, 
remote attacker can exploit this to cause the device to reboot.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10987
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3b4a2e3");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10987.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if ("MX" >!< model) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

// 17.2 versions starting from17.2R2-S6, 17.2R3 and later releases, prior to 17.2R3-S3;
if (ver =~ "^17.2R1(?=$|[^0-9])" || ver =~ "^17\.2R2(-S[1-5])?(?=$|[^0-9-])")
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
fixes['17.2'] = '17.2R3-S3';

// 17.3 versions starting from 17.3R2-S4, 17.3R3-S2 and later releases, prior to 17.3R2-S5, 17.3R3-S5;
if (ver =~ "^17.3R1(?=$|[^0-9])" || ver =~ "^17.3R2(-S[1-3])?(?=$|[^0-9-])" || ver =~ "^17.3R3(-S1)?(?=$|[^0-9-])")
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
else if (ver =~ "^17.3R2(?=$|[^0-9])")
  fixes['17.3'] = '17.3R2-S5';
else
  fixes['17.3'] = '17.3R3-S5';

// 17.4 versions starting from 17.4R2 and later releases, prior to 17.4R2-S7,17.4R3;
if (ver =~ "^17.4R1(?=$|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
fixes['17.4'] = '17.4R2-S7';

// 18.1 versions starting from 18.1R2-S3, 18.1R3 and later releases, prior to 18.1R3-S6;
if (ver =~ "^18.1R1(?=$|[^0-9])" || ver =~ "^18.1R2(-S[12])?(?=$|[^0-9-])")
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
fixes['18.1'] = '18.1R3-S6';

// 18.2 versions starting from18.2R1-S1, 18.2R2 and later releases, prior to 18.2R3-S2;
if (ver =~ "^18.2R1$") audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
fixes['18.2'] = '18.2R3-S2';

// 18.2X75 versions prior to 18.2X75-D51, 18.2X75-D60;
fixes['18.2X75'] = '18.2X75-D51';
fixes['18.3'] = '18.3R3';
fixes['18.4'] = '18.4R2';
fixes['19.1'] = '19.1R1-S3';
fixes['19.2'] = '19.2R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);

