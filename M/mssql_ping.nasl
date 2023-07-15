#

# Changes by Tenable:
# - Revised plugin title (6/8/09)


include("compat.inc");

if(description)
{
 script_id(10674);
 script_version ("1.29");
 script_cvs_date("Date: 2018/03/13 18:52:33");

 script_name(english:"Microsoft SQL Server UDP Query Remote Version Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to determine the remote SQL server version." );
 script_set_attribute(attribute:"description", value:
"Microsoft SQL server has a function wherein remote users can query the
database server for the version that is being run.  The query takes
place over the same UDP port that handles the mapping of multiple SQL
server instances on the same machine. 

It is important to note that, after Version 8.00.194, Microsoft
decided not to update this function.  This means that the data
returned by the SQL ping is inaccurate for newer releases of SQL
Server." );
 script_set_attribute(attribute:"solution", value:
"If there is only a single SQL instance installed on the remote host,
consider filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
script_end_attributes();

 script_summary(english:"Microsoft's SQL UDP Info Query");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2018 H D Moore");
 script_family(english:"Databases");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

##
# data returned will look like:
#
#   ServerName;REDEMPTION;InstanceName;MSSQLSERVER;IsClustered;No;Version;8.00.194;tcp;1433;np;\\REDEMPTION\pipe\sql\query;;
#
##

# this magic info request packet
req = raw_string(0x02);


if(!get_udp_port_state(1434))exit(0);

soc = open_sock_udp(1434);


if(soc)
{
  send(socket:soc, data:req);
  r  = recv(socket:soc, length:4096);
  close(soc);
  if(!r) exit(0);

  set_kb_item(name:"MSSQL/UDP/Ping", value:TRUE);

  if ("ServerName" >< r)
  {
    r = strstr(r, "ServerName");
    report = "";
    servers = split(r, sep:";;", keep:FALSE);

    foreach server (servers)
    {
      fields = split(server, sep:";", keep:FALSE);
      nfields = max_index(fields);

      max_label_len = 0;
      for (i=0; i<nfields; i+=2)
      {
        label = fields[i];
        if (strlen(label) > max_label_len) max_label_len = strlen(label);
      }

      instance = "";
      port = 0;
      for (i=0; i<nfields; i+=2)
      {
        label = fields[i];
        value = fields[i+1];
        report += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + value + '\n';

        if (label == "tcp" && int(value) > 0 && int(value) <= 65535)
        {
          port = value;
          set_kb_item(name:"mssql/possible_port", value:value);
        }

        if (label == "InstanceName") instance = value;
      }

      if (!empty_or_null(instance) && port != 0)
        set_kb_item(name:"MSSQL/" + port + "/InstanceName", value:instance);

      report += '\n';
    }

    if (max_index(servers) > 1) s = "s";
    else s = "";

    report =
      '\n' +
      "A 'ping' request returned the following information about the remote" + '\n' +
      "SQL instance" + s + ' :\n' +
      '\n' +
      report;

    security_note(port:1434, protocol:"udp", extra:report);
    set_kb_item(name:"mssql/udp/1434", value:TRUE);
  }
}
