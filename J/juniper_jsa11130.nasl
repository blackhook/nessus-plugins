#TRUSTED 61faa0a16d14de4428ae64241032d688f4a1adc828cbae5c2e8b86c22e07848cfbac8c8631a3b3c63b8b19d562aaf45f54a0fd7e72d53a3ce24dd306072c46d16d04a6f1e1f91c963135be08133c6dfbca50e3691ed7bb4a668345887022dfd90b9d7dd5e5858e4fdf8f3c151b4787d65877906adb7073873e59c2da14344136c9689a4dbf421fab9bb863f958115366852b821d691b34888ee4169e684fe4287d794cd208ab8b2a75cb56abbd7b4c4a23c76e1fb53dc0e90ae88470492f777b422837f9d1ced7afbca04179e95f94f6e96d86f0cb50156b67eeae2bf9b44277bbba6a297c5dcae3ad4f8f1ccf4e63d0983375a8de6e09284066aebf1bc987ff538acf0f224232201dc0807e3df3c28e76dc1842d95628b0c1db5f586853faa7c0dd6710c37061b87a1f42032e82ab426934411e28dd0bf10ac8fc1d206ebde151e60a4f0d11f45c88c367208e1595e0fb0b45053baef69feda737795982b8756a7c6668ccf926ac0247858aeb7febfdcb3c716053cf9b3df140d945cc85a723382492dccb320eb9340c455a5972007d4361af2bbbf1e23f6bf5cc3961334450b65e564c5cf18689cf702e6d6de1a2e6f617526251fbb418e5f994b39df37afb3206d564072a837d7bb71113403a58b79458e021304c964cea2d983e09e6a59153f86ab28395a89257d14a13eb21a5343e6ba187a387997b17789d5e3dd56afc
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148682);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/02");

  script_cve_id("CVE-2021-0235");
  script_xref(name:"JSA", value:"JSA11130");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11130)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11130
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11130");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11130");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var model = get_kb_item_or_exit('Host/Juniper/model');

# Only versions 20.x and above include vSRX
if (model !~ "^(vSRX[0-9]+|SRX((15|41|42|46)[0-9]{2}|5[0-9]{3})([^0-9]|$))")
  audit(AUDIT_DEVICE_NOT_VULN, model);
if (model =~ "^vSRX" && ver !~ "^20\.[1-4]([^0-9]|$)")
  audit(AUDIT_DEVICE_NOT_VULN, model);

var vuln_ranges = [
  {'min_ver':'18.3',   'fixed_ver':'18.3R1'},
  {'min_ver':'18.4',   'fixed_ver':'18.4R1'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R1'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3',   'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4',   'fixed_ver':'19.4R2-S4'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S2'},
  {'min_ver':'20.1',   'fixed_ver':'20.1R2',    'fixed_display':'20.1R2, 20.1R3'},
  {'min_ver':'20.2',   'fixed_ver':'20.2R2-S1', 'fixed_display':'20.2R2-S1, 20.2R3'},
  {'min_ver':'20.3',   'fixed_ver':'20.3R1-S2', 'fixed_display':'20.3R1-S2, 20.3R2'},
  {'min_ver':'20.4',   'fixed_ver':'20.4R1',    'fixed_display':'20.4R1, 20.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf;

# Only non-vSRX requires SPC to be vulnerable
if (model !~ "^vSRX")
{
  var affected_spc = FALSE;

  # SPC check
  buf = junos_command_kb_item(cmd:'show chassis hardware models');
  if (junos_check_result(buf))
  {
    override = FALSE;

    # SPC2
    if (buf =~ "SPC-?2")
      affected_spc = TRUE;

    # SPC3 (only for SRX5000 series and branches after 18.3)
    if (buf =~ "SPC-?3" && ver !~ "^18.3" && model =~ "^SRX5[0-9]{3}([^0-9]|$)")
      affected_spc = TRUE;
  }

  if (!affected_spc)
    audit(AUDIT_HOST_NOT, 'using an affected SPC');
}

# Tenant config check
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (junos_check_result(buf))
{
  override = FALSE;
  # Advisory specifies "tenant services". The most basic tenant config requies a "set tenants <TENANT>" command
  if (!junos_check_config(buf:buf, pattern:"^set tenants"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
