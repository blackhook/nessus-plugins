#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102075);
  script_version ("1.3");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2017-2348");
  script_xref(name:"JSA", value:"JSA10800");

  script_name(english:"Juniper Junos jdhcpd IPv6 UDP DoS (JSA10800)");
  script_summary(english:"Checks the Junos version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Juniper Junos device is affected by a denial of service vulnerability
in the jdhcpd daemon when handling invalid IPv6 UDP packets. An
unauthenticated, remote attacker can exploit this, via specially
crafted IPv6 UDP packets, to consume available CPU resources,
resulting in an interruption of the DHCP service.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10800");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10800.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("junos_kb_cmd_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['15.1']   = '15.1R4';
fixes['15.1F2'] = '15.1F2-S18';

if (model =~ "^QFabric")
  fixes['14.1X53'] = '14.1X53-D12';

if (model =~ "^SRX")
  fixes['15.1X49'] = '15.1X49-D80';

if (model =~ "^NFX")
  fixes['15.1X53'] = '15.1X53-D51';

if (model =~ "^(QF|E)X")
  fixes['14.1X53'] = '14.1X53-D12';
  fixes['15.1X53'] = '15.1X53-D51';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_HOLE);
