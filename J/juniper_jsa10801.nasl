#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102076);
  script_version ("1.3");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2017-2349");
  script_xref(name:"JSA", value:"JSA10801");

  script_name(english:"Juniper Junos SRX IDP Remote Command Injection (JSA10801)");
  script_summary(english:"Checks the Junos version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Juniper Junos device is affected by a remote command injection
vulnerability in the IDP feature due to improper validation of
user-supplied input. An authenticated, remote attacker can exploit
this to execute arbitrary shell commands with elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10801.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^SRX")
  audit(AUDIT_HOST_NOT, 'a SRX device');

fixes = make_array();

fixes['12.1X44'] = '12.1X44-D60';
fixes['12.1X46'] = '12.1X46-D50';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3X48'] = '12.3X48-D20';
fixes['15.1X49'] = '15.1X49-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_HOLE);
