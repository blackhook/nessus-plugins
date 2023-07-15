#TRUSTED 6ee1efc7b68676fcab43a1b2b4458b5da2a9c1c14a358c92783aecc2e86ffa829fddad7a090eab57d982adbc960313b317d78b30f259167f784236d1ee9641725ad20ce07e8079ad93aab87941d802a748f7ac74e4ebf2571e49d5d0b43c592a872fbb843bd5bb6343b87ccc69b111c90ee2868523eaabda6c3012b507582390547da6a142b00fc186c404c5c9443043fc3dbda378b8687b16c24d5a611c79b49a4b5f0e5026493d0d752f3000e1de75cad0eb0d8737582fe8c192a795fedb2d1e684549aeec4a2ee14be69f124ce69a092ece13a8af7dcdd02596b781752227f918f82fcc587ed3520d11fe11a34e4b3ad297311bcce1c7afc5bc4b62c8469bec6aae7012d6c16caeb319310216dd1604908cd68493beeef5ad3e49a2791808d3730b5e06881989f536f16b1b76019e737984c77b11deab979d957bd737435dc9f776a7d3d812a5a09c49c2a63ef104ae2dc8c0ee623c935541492ce0d0095d4ddcf4db2390d980df8ee0cda1b6edc802c4ceb6aa34d9e4784fe2b9f6fa2960bd4c6eff447aeb05f8c9da0e1ff886fffb909e15ba8abcd3687ba3adc2e12d4b1ac8ce9b6e8b6392dcf72634e665d3f659d4393eef74dce28a20f60f6eec92b791ae3f4f50816b519c1c31fe4aaa6acda5dc7df70770a8a9b4851b7355d4e2643c8353b97d5ae4809a1903491c9be091008a857ecef66538e64e2242d702d4e6
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159063);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/22");

  script_cve_id("CVE-2022-22156");
  script_xref(name:"JSA", value:"JSA11264");
  script_xref(name:"IAVA", value:"2022-A-0028");

  script_name(english:"Juniper Junos OS Improper Certificate Validation (JSA11264)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11264
advisory. An Improper Certificate Validation weakness in the Juniper Networks Junos OS allows an attacker to perform
Person-in-the-Middle (PitM) attacks when a system script is fetched from a remote source at a specified HTTPS URL, which
may compromise the integrity and confidentiality of the device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11264");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11264");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22156");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0', 'fixed_ver':'18.4R2-S9'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S9'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2-S3'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S7'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2', 'fixed_display':'20.1R2-S2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2-S1', 'fixed_display':'20.3R2-S1, 20.3R3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1-S1', 'fixed_display':'21.1R1-S1, 21.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set event-options event-script file .* source .* refresh", multiline:TRUE) &&
      !preg(string:buf, pattern:"^set system scripts (commit|event|extension-service|op|snmp) file .* refresh-from", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
