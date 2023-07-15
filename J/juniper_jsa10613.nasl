#TRUSTED 59ace462f8561f84ebd33848e0ebe82c09bfbfa98cd0ab512ccbf459f0033f1c7d2f22fbce29ce81ba536e5ef580fded0b0b80dd4dd46205fda7d33062608a4142aca7c51fd2a5a0bb5b0f50b7c270a315491fdffecfc099c25d7bedcdfdef618db5578fafc75bf55cd255eeab2f6b87f326a648ddf585c60fe2e2ba27bf752caed97212d384ba2692d7d39235b86e5c45a76feaac299840cb52e5824e74366a73761bda640a91779bd1db4760e8a1869bdaf8324e9d888f7cb32b14f2528ab9a7601012b898cee52d3c8d2c6b148d353931d775d8457bf8c40f769674a378043fd8f0291ccb4eae4946ce0e95caabc61a0f6840d4b2f225a11d0e0f235ab8a7cbdc8fe59502d467bd239369c71796112c33706a93cc311036ebd26ba5f0e71b5d9f0680f0e6776188de401d24792c1874cb8665d606a56686753feda41c1fbcb808f84fd7aa257855b9a3c755f5fc90d1dcffd70789a86bb17f8db70823d080be354e54baec5a61ccd5bc341a03bbf8b38545e7de4bafe56df4048eaafc2159a352e3c9a63e0fa4b7e649f50f9942ed68e02a422a04ed94be59fff0c0a07156379bd17fa5224e229eaf9785006c0336ecc14cabb92e7855cd8c74e59955c42adb44da8b1a465d629e0106db53897ca224e7785540b842ba34f9f6278e810c89aec79a98a908ee5e55cac3778642c3d1a1fa07dce5da5ef1b9c54e0043c8ece8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77756);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2013-5211");
  script_bugtraq_id(64692);
  script_xref(name:"CERT", value:"348126");
  script_xref(name:"EDB-ID", value:"33073");
  script_xref(name:"ICSA", value:"14-051-04");
  script_xref(name:"JSA", value:"JSA10613");

  script_name(english:"Juniper Junos NTP Server Amplification Remote DoS (JSA10613)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability in the NTP daemon related
to the handling of the 'monlist' command. A remote attacker can
exploit this by forging a request that results in a distributed denial
of service.

Note that this issue only affects devices with NTP client or server
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10613");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10613.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
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

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

# Junos OS 14.1R1 release date
if (compare_build_dates(build_date, '2014-06-07') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R12';
fixes['12.1']    = '12.1R10';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D15';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R8';
fixes['12.3']    = '12.3R7';
fixes['13.1']    = '13.1R4-S2';
fixes['13.2']    = '13.2R4';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for NTP
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system ntp server";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because neither a NTP client nor server are enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
