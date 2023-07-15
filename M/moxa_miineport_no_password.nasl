#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93527);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-2286");

  script_name(english:"Moxa MiiNePort Blank Default Telnet Password");

  script_set_attribute(attribute:"synopsis", value:
"The remote device has a telnet service protected with blank default
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote device has a telnet service protected by blank default
credentials that allow privileged access to the device.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2016/May/7");
  script_set_attribute(attribute:"solution", value:
"Change the blank default password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:T/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2286");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:moxa:miineport_e1_4641_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:moxa:miineport_e1_7080_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:moxa:miineport_e2_1242_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:moxa:miineport_e2_4561_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:moxa:miineport_e3_firmware");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include('global_settings.inc');

app    = 'Moxa MiiNePort';
port   = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);
banner = get_telnet_banner(port:port);

if (banner !~ "Model name *: MiiNePort")
  audit(AUDIT_NOT_LISTEN, app, port);

if (
    '<< Main Menu >>' >< banner
    &&
    'DIO settings' >< banner
    &&
    'Serial command mode settings' >< banner
    &&
    'Configuration tools' >< banner
)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    request    : make_list("telnet <host-ip>"),
    output     : banner,
    line_limit : 20
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port);

