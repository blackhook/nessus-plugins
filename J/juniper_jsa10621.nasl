#TRUSTED 7f5a26edd72779b29cc9618ba87d163226cc70c4483a88989f143d1187d483beea424c05f2f1e10e6801baac8310b6061f933eb7d2cda3422334854384233eb803790f0c5209bd39bf264fe0a891871946f84d6fbaf2546787043073a8f6495138d2c492ad5ed564055328c004d45e1d6f5d6651cb307ea24e3eef4074809c452990d7794bf0184d47152001a820307e1298589cd289eeb2bcecc0e973f3e95952ae498269581185d463aa860e3abbbff516cd07831e22653a17b5dce7b5a0bee96758a443ba292e762f4ccdf55efdd48a262dbd2015e594ca33008a11c842c0d65886374d6d1b20f57adc5be9b86f0a7c6fda58e5753c7b4acfe7a50e4d6b408b77bdc0df2b87164923ef765cdf590ec9a3177ab7e51db4e92b8ec71f70526096d467ba1d9954303cabff94a94dfa0814e16d2e3a9198345b840b5e3bd1a0ec3037152a2a69e4fec56540969b81816b153d400e90c5adc63230daaea2bf985b79009a54bf3e33901961354a0a4efee4a7d1cfb6287f774af606eb9d78259cf60e0eceab509749afce4b2368c6802ca240a67b2767535e015ba51abbff068b0d49b810c43c9de318727ce378f2fa1d906478eefa33eca0348be462fc5b9699270faae5fec6922d21b3d85b347078f105f644f5c1fb25e3d9e8ac340c9095853b3309413510ea2d52c3e33e7bf2bcafeecf5106177c8ddd96fde17ff7aacf1298
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73495);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-2713");
  script_bugtraq_id(66764);
  script_xref(name:"JSA", value:"JSA10621");

  script_name(english:"Juniper Junos MX and T4000 Series MPC Reboot DoS (JSA10621)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability. The issue exists in
MX and T4000 series routers that use either Trio-based or Cassis-based
PFE modules. An attacker can exploit this vulnerability by sending a
crafted IP packet to cause the MPC to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10621");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10621.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (model !~ "(^MX[0-9]|^MX-MPC[1-4]|^CHAS-MX|^MPC[4-]|^T4000-FPC5)")
  audit(AUDIT_HOST_NOT,
    'an MX Series or T4000 router that supports Trio or Cassis-based PFEs');

if (compare_build_dates(build_date, '2014-03-20') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '12.3R4-S3')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['11.4'] = '11.4R11';
fixes['12.1'] = '12.1R9';
fixes['12.2'] = '12.2R7';
fixes['12.3'] = '12.3R5';
fixes['13.1'] = '13.1R4';
fixes['13.2'] = '13.2R2';
fixes['13.3'] = '13.3R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show chassis hardware");
if (buf)
{
  # PFE modules part numbers
  # https://kb.juniper.net/InfoCenter/index?page=content&id=KB25385
  part_numbers = make_list(
    # Trio-based PFE modules
    "750-028381",
    "750-031087",
    "750-028395",
    "750-031092",
    "750-038489",
    "750-038490",
    "750-031089",
    "750-028393",
    "750-028391",
    "750-031088",
    "750-028394",
    "750-031090",
    "750-024884",
    "750-038491",
    "750-038493",
    "750-038492",
    "750-028467",
    "711-031594",
    "711-031603",
    "711-038215",
    "711-038213",
    "711-038211",
    "711-038634",
    # Cassis-based PFE modules
    "750-045173",
    "750-045372",
    "750-037358",
    "750-037355",
    "750-054564",
    "750-046005",
    "750-045715",
    "750-054563",
    "750-044130"
  );

  foreach part_number (part_numbers)
  {
    if (part_number >< buf)
    {
      override = FALSE;
      break;
    }
  }
  if (override) audit(AUDIT_HOST_NOT, 'affected because no Trio-based or Cassis-based
PFE modules were detected');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
