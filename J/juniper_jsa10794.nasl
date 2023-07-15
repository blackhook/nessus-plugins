#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102707);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/13 15:08:46");

  script_cve_id("CVE-2017-2346");
  script_xref(name:"JSA", value:"JSA10794");

  script_name(english:"Juniper Junos ALG Fragmented Traffic Handling MS-MPC / MS-MIC Service PIC DoS (JSA10794)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Juniper Junos device is affected by a denial of service vulnerability
in the Application Layer Gateway (ALG) that is triggered when handling
a large amount of fragmented packets. An unauthenticated, remote
attacker can exploit this to crash an MS-MPC or MS-MIC service
physical interface card (PIC).

Note that the device is only vulnerable if NAT or stateful-firewall
rules are configured with ALGs enabled ");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10794");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10794. Alternatively, disable NAT and the
stateful-firewall if they are not required.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");
  
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");
include("global_settings.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
override = TRUE;
check_model(
  model:model,
  flags:MX_SERIES,
  exit_on_fail:TRUE
);

# Only devices with NAT or FW rules that use ALGs are affected
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();
if(ver =~ "^14\.1X55-D3[0-9]([^0-9]|$)")  fixes['14.1X55'] = '14.1X55-D35';
if(ver =~ "^14\.2R7")    fixes['14.2R'] = '14.2R7-S4'; # or 14.2R8 
if(ver =~ "^15\.1R5")    fixes['15.1R'] = '15.1R5-S2'; # or 15.1R6
if(ver =~ "^16\.1R[23]") fixes['16.1R'] = '16.1R3-S2'; # or 16.1R4

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
