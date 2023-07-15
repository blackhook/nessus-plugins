#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103671);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12232");
  script_bugtraq_id(101044);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc03809");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-rbip-dos");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS Software Integrated Services Routers Generation 2 denial of service (cisco-sa-20170927-rbip-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability in it's handling of ethernet frames. An
unauthenticated, remote attacker can exploit this, via a specially
crafted ethernet frame, to cause the switch to stop processing
traffic, requiring a device restart to regain functionality.

This vulnerability only affects Cisco ISR Generation 2 devices.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-rbip-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d64402f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvc03809.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12232");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

vuln_versions = make_list(
  '15.3(1)T',
  '15.2(1)T',
  '15.1(4)M3',
  '15.2(4)M',
  '15.1(4)M',
  '15.1(4)M1',
  '15.1(4)M2',
  '15.2(2)T',
  '15.2(3)T',
  '15.1(4)M6',
  '15.1(4)M5',
  '15.1(4)XB4',
  '15.1(4)M4',
  '15.1(4)M0a',
  '15.1(4)XB5',
  '15.2(1)GC',
  '15.1(4)M0b',
  '15.2(1)T1',
  '15.2(1)T3',
  '15.2(1)T2',
  '15.3(2)T',
  '15.2(1)T4',
  '15.1(4)M7',
  '15.1(4)XB6',
  '15.2(1)GC1',
  '15.1(4)XB5a',
  '15.2(1)GC2',
  '15.2(2)T1',
  '15.1(4)XB7',
  '15.1(4)M3a',
  '15.2(3)T3',
  '15.2(3)T4',
  '15.2(3)T1',
  '15.2(2)T3',
  '15.2(3)T2',
  '15.2(2)T2',
  '15.2(2)T4',
  '15.2(3)XA',
  '15.4(1)T',
  '15.1(4)XB8',
  '15.2(2)GC',
  '15.1(4)XB8a',
  '15.2(3)GC',
  '15.2(4)M1',
  '15.2(2)JA',
  '15.2(4)M2',
  '15.2(4)M4',
  '15.2(4)M3',
  '15.2(4)M5',
  '15.2(4)M8',
  '15.2(4)M10',
  '15.2(4)M7',
  '15.2(4)M6',
  '15.2(4)M9',
  '15.1(4)M10',
  '15.2(2)JA1',
  '15.1(4)M8',
  '15.2(1)T3a',
  '15.1(4)GC',
  '15.2(4)XB10',
  '15.2(2)JB1',
  '15.2(2)JB',
  '15.3(1)T1',
  '15.3(1)T2',
  '15.2(2)JAX',
  '15.3(3)M',
  '15.3(1)T3',
  '15.1(4)GC1',
  '15.2(3)GCA',
  '15.3(1)T4',
  '15.2(4)XB11',
  '15.2(3)GC1',
  '15.2(4)JA',
  '15.3(2)T1',
  '15.3(2)T2',
  '15.3(2)T3',
  '15.2(2)JB2',
  '15.4(2)T',
  '15.2(2)JN1',
  '15.2(4)JA1',
  '15.2(3)GCA1',
  '15.3(3)M1',
  '15.3(3)M2',
  '15.2(4)GC',
  '15.3(3)M3',
  '15.3(3)M5',
  '15.4(3)M',
  '15.2(2)JN2',
  '15.2(4)JN',
  '15.2(2)JAX1',
  '15.2(4)JB',
  '15.2(2)JB3',
  '15.1(4)M9',
  '15.3(2)T4',
  '15.3(3)M4',
  '15.2(4)JAZ',
  '15.2(4)JB1',
  '15.3(3)XB12',
  '15.2(4)JB2',
  '15.4(1)CG',
  '15.4(1)T2',
  '15.4(1)T1',
  '15.4(1)T3',
  '15.2(4)JB3',
  '15.2(4)JB3a',
  '15.2(2)JB4',
  '15.5(1)T',
  '15.2(4)JB4',
  '15.2(1)EY1',
  '15.2(4)JB3h',
  '15.1(4)GC2',
  '12.4(25e)JAO3a',
  '15.2(4)JB3b',
  '15.2(4)GC1',
  '12.4(25e)JAO20s',
  '15.2(4)JB3s',
  '15.3(3)M6',
  '15.3(3)JN',
  '15.4(1)CG1',
  '15.2(4)JB5h',
  '15.4(2)CG',
  '15.2(4)JB5',
  '15.2(4)M6b',
  '15.5(3)M',
  '15.2(4)JB5m',
  '15.2(4)GC2',
  '15.3(3)JA75',
  '15.3(3)JA',
  '15.4(2)T1',
  '15.3(3)JA100',
  '15.4(3)M1',
  '15.2(4)M6a',
  '15.3(3)JAB',
  '15.4(2)T3',
  '15.1(4)M11',
  '15.2(4)GC3',
  '15.2(4)JB6',
  '15.4(2)T2',
  '15.3(3)JAA',
  '15.4(3)M2',
  '15.5(1)T1',
  '15.4(1)T4',
  '15.3(3)JA1n',
  '15.3(3)JA1m',
  '15.3(3)JA1',
  '15.3(3)SA',
  '15.6(1)T',
  '15.5(2)T',
  '15.3(3)JA2',
  '15.2(2)E3',
  '15.2(2)JB5',
  '15.4(3)M3',
  '15.3(3)JNB',
  '12.4(25e)JAP3',
  '12.4(25e)JAO5m',
  '15.1(4)M12',
  '15.2(3)EA1',
  '15.2(1)EY2',
  '15.2(2)JA3',
  '15.2(2)JB6',
  '15.2(4)JB7',
  '15.2(4)JB8',
  '15.3(3)JA3',
  '15.3(3)JA4',
  '15.3(3)JA5',
  '15.3(3)JA76',
  '15.3(3)JA77',
  '15.3(3)JAX',
  '15.3(3)JAX1',
  '15.3(3)JAX2',
  '15.3(3)JAX3',
  '15.3(3)JB',
  '15.3(3)JB75',
  '15.3(3)JBB',
  '15.3(3)JBB1',
  '15.3(3)JBB50',
  '15.3(3)JN3',
  '15.3(3)JN4',
  '15.3(3)JN5',
  '15.3(3)JNB1',
  '15.3(3)JNB2',
  '15.3(3)M7',
  '15.4(3)M4',
  '15.4(3)SN2',
  '15.4(2)T4',
  '15.5(2)SN0a',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.6(2)T',
  '15.5(3)M1',
  '15.3(3)JBB2',
  '15.3(3)M8',
  '15.3(3)JC',
  '15.5(3)SN1',
  '15.3(3)JN6',
  '15.3(3)JN7',
  '15.5(3)M0a',
  '15.3(3)JBB3',
  '15.3(3)JNC',
  '15.3(3)JBB4',
  '15.3(3)JBB5',
  '15.2(4)M11',
  '15.3(3)JN8',
  '15.3(3)JNB3',
  '15.3(3)JBB6',
  '15.3(3)JA6',
  '15.3(3)JNP',
  '15.5(2)T3',
  '15.4(3)M5',
  '15.5(3)M2',
  '12.4(25e)JAP1n',
  '15.6(1)T0a',
  '15.3(3)JBB7',
  '15.3(3)JBB8',
  '15.3(3)JC30',
  '15.6(1)T1',
  '15.3(3)JNC1',
  '15.3(3)JNP1',
  '15.2(3)E2a',
  '15.5(2)XB',
  '15.3(3)JC1',
  '15.5(3)M2a',
  '15.5(3)S2a',
  '15.3(3)JN9',
  '15.3(3)JNB4',
  '15.3(3)JBB6a',
  '15.5(3)M3',
  '15.2(3)EX',
  '15.5(2)T4',
  '15.3(3)JPB',
  '15.3(3)JD',
  '15.6(3)M',
  '15.4(3)M6',
  '15.3(3)JA7',
  '15.5(1)T4',
  '15.3(3)JA8',
  '15.3(3)JNP2',
  '15.6(2)S0a',
  '15.6(2)T1',
  '15.4(3)S5a',
  '15.5(3)S2b',
  '15.6(1)S1a',
  '15.6(1)T2',
  '15.6(2)T0a',
  '12.4(25e)JAP9',
  '15.3(3)JPB1',
  '15.3(3)M9',
  '15.2(4)EC',
  '15.3(3)JC2',
  '15.1(2)SG7a',
  '15.5(3)S3a',
  '15.3(3)JC50',
  '15.3(3)JC51',
  '15.6(2)S2',
  '15.6(2)T2',
  '15.3(3)JND',
  '15.3(3)JA10',
  '15.3(3)JN10',
  '15.3(3)JC3',
  '15.2(4)EB',
  '15.3(3)JE',
  '15.3(3)JPD',
  '15.5(3)M4',
  '15.3(3)JC4',
  '15.6(3)M0a',
  '15.1(4)M12a',
  '15.3(3)M8a',
  '15.3(3)JPC2',
  '15.4(3)M6a',
  '15.3(3)JPB2',
  '15.5(3)S4a',
  '15.5(3)M4a',
  '15.5(3)S4b',
  '15.3(3)JC5',
  '15.2(2)E5b',
  '15.3(3)JN11',
  '15.3(3)JD2',
  '15.3(3)JD3',
  '15.3(3)JND1',
  '15.5(3)M4b',
  '15.2(5a)E1',
  '15.5(3)M4c',
  '15.6(2)SP1b',
  '15.5(3)S4d',
  '15.6(2)SP1c',
  '15.3(3)JC6',
  '15.2(4a)EA5',
  '15.5(3)S4e',
  '15.3(3)JNB6',
  '15.3(3)JPC3',
  '15.3(3)JDA3',
  '15.5(3)S5a',
  '15.4(3)S6b',
  '15.4(3)S7a',
  '15.3(3)JNC4',
  '15.4(3)M7a',
  '15.3(3)JD4',
  '15.5(3)S5b',
  '15.6(2)S3',
  '15.3(3)JA11',
  '15.3(3)JC7',
  '15.6(2)SP2a',
  '15.3(3)JND2',
  '15.3(3)JCA7',
  '15.0(2)SQD7',
  '15.6(1)T3',
  '15.2(5)E2a',
  '15.2(5)E2b',
  '15.3(3)JE1',
  '15.3(3)JND3',
  '15.3(3)JN12'
);

# Check for vuln version
foreach version (vuln_versions)
{
  if (version == ver)
  {
    flag++;
    break;
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    version  : ver,
    bug_id   : 'CSCvc03809'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", ver);
