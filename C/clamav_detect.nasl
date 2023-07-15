#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39436);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_xref(name:"IAVT", value:"0001-T-0574");

  script_name(english:"ClamAV Version Detection");
  script_summary(english:"Sends a VERSION command to clamd");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote ClamAV
installation." );
  script_set_attribute(attribute:"description", value:
"By sending a 'VERSION' command to the remote clamd antivirus daemon,
it is possible to determine the version of the remote ClamAV software
installation." );
  script_set_attribute(attribute:"see_also", value:"http://www.clamav.net/" );
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/clamd", 3310);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");

port = get_kb_item("Services/clamd");
if (!port) port = 3310;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


# Send a VERSION command.
req = "VERSION";
send(socket:soc, data:req+'\r\n');

res = recv_line(socket:soc, length:128);
if (!strlen(res) || "ClamAV " >!< res)
  audit(AUDIT_NOT_LISTEN, "ClamAV", port);

# Extract it.
res = chomp(res);
info = split(res, sep:'/', keep:FALSE);
version = info[0] - 'ClamAV ';
sigs = info[1];
sigs_date = info[2];

if (version)
{
  set_kb_item(name:"Antivirus/ClamAV/installed", value:TRUE);
  set_kb_item(name:"Antivirus/ClamAV/version", value:version);

  if (!isnull(sigs))
    set_kb_item(name:"Antivirus/ClamAV/sigs", value:sigs);
  else
    sigs = "Unknown";

  if (!isnull(sigs_date))
    set_kb_item(name:"Antivirus/ClamAV/sigs_date", value:sigs_date);
  else
    sigs_date = "Unknown";

  extra = make_array();
  extra['Virus signatures version'] = sigs;
  extra['Virus signatures date'] = sigs_date;
  register_install(
    vendor:"ClamAV",
    product:"ClamAV",
    app_name:'ClamAV',
    port:port,
    path:'/',
    version:version,
    cpe:'cpe:/a:clamav:clamav',
    extra:extra
  );

  if (report_verbosity > 0)
  {
    report =
      '\nThe remote host responded to a "VERSION" command with the following'+
      '\ninformation :\n'+
      '\nClamAV version : '+version+
      '\nVirus signatures version : '+sigs+
      '\nVirus signatures date : '+sigs_date+'\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
audit(AUDIT_SERVICE_VER_FAIL, "ClamAV", port);
