#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100620);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"EDB-ID", value:"41978");

  script_name(english:"Oracle GoldenGate Manager < 12.2.0.1.1 OBEY Command ggserr.log File Handling RCE");

  script_set_attribute(attribute:"synopsis", value:
"The Oracle GoldenGate Manager application running on the remote host
is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle GoldenGate
Manager application running on the remote host is prior to 12.2.0.1.1.
It is, therefore, affected by a remote code execution vulnerability
due to improper handling of 'OBEY' commands and the ggserr.log file.
An unauthenticated, remote attacker can exploit this to execute
arbitrary code by entering a 'SHELL' command into the error log and
then executing the error log via the 'OBEY' command.

Note that newer versions of Oracle GoldenGate Manager do not fix this
issue but instead introduce access controls that disallow use of
'OBEY' by default.");
  script_set_attribute(attribute:"see_also", value:"https://blog.silentsignal.eu/2017/05/08/fools-of-golden-gate/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GoldenGate Manager version 12.2.0.1.1 and use
appropriate access controls to disallow the use of the 'OBEY' command.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("golden_gate_manager_detect.nbin");
  script_require_keys("gg_manager/present");
  script_require_ports("Services/gg_manager", 7809);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
get_kb_item_or_exit('gg_manager/present');

appname = 'Oracle GoldenGate Manager';
port = get_service(svc:'gg_manager', default:7809, exit_on_fail:TRUE);
version = get_kb_item_or_exit('gg_manager/' + port + '/version');

fix = "12.2.0.1.1";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, version);
