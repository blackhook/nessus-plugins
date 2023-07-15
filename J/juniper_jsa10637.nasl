#TRUSTED a5b3148c2ba8b98c4a3ca51e50fe74b47e2ae8da11d770988cad68371b23010b36fbcdf9e91f6cf39bdf64befb4b9a1719beeefb2d2e26b772977344374d551ca66d19a428b0303adce3abbcd43cb176380f1427726eeaafcfa622bd682e36cc78b72611df4380cbea9e037a71cff8ad62dd0134f879d6e31519c3e64c4d7deee3b0db8cdb1a3d0b6c9f2861f8253f439b0f98c1a2083b8e7c1ad3dcdd4d07965c83cf348ebbd31f7afbed6d81abec7db1a75605a3cfd49b244f28af1f7e2e8700d584de5eeec2b1bcf966297263645f9a66088ff13aebe020ae884f4a8bd63b81c0debccad9956848f935587c1b162c38758f62ebdd8542b86c5c974b3bb61016bcfeb807847e4718b5454c24e7ba90a83ba84f3a5a805952dfd5ee55c9d0a6b73dfb098b9be477ff66c438a9ef5faa1bb44b85dc311682cd7683e118b0a4102b1817599c5497d34f7f5686c2f5f88970505ff5edc9dbeeb3fe2b357bbb9374134c978a4c91b7489f01020a2a9e884adcbceaeec351ad30996f7d6e2abfdebe36d8374b14c4a40958caa1c9a7dc53b47dc19cafb4ebd526c0cabddf903bc641a5aab16c2286914938d965ee7e94d08c5200da49e62f90913e9a69bfa04ad618f3c7bd4b5345905df91d85687e673e0916480d6e4278219b13de5dd61a2135af61b42c5e9622bee3516acba18b37fd165781954ba568c2e862620f1b89dedb91
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76505);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-3819");
  script_bugtraq_id(68539);
  script_xref(name:"JSA", value:"JSA10637");

  script_name(english:"Juniper Junos Invalid PIM DoS (JSA10637)");
  script_summary(english:"Checks the Junos version, build date and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability. A remote attacker,
by sending a specially crafted PIM packet, can crash and restart the
RPD routing process.

Note that this issue affects all PIM routers that are configured to
use Auto-RP.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10637");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10637.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver        = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

# Junos OS 14.1R1 release date
if (compare_build_dates(build_date, '2014-06-26') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R12';
fixes['12.1']    = '12.1R10';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R8';
fixes['12.3']    = '12.3R7';
fixes['13.1']    = '13.1R4';
fixes['13.2']    = '13.2R4';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if Auto-RP is enabled 
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols pim rp auto-rp announce";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because Auto-RP is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
