#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(69322);
 script_version("1.9");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

 script_name(english:"HP Switch Identification");
 script_summary(english:"Obtains the version of the remote HP switch");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the model, serial number and / or software
version for the remote HP switch.");
 script_set_attribute(attribute:"description", value:
"The remote host is an HP switch. It is possible to read the model,
serial number, and/or software version by connecting to the switch via
SSH or by using SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:procurve_switch");

 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Service detection");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl");
 script_require_ports("Host/HP_Switch", "SNMP/sysDesc");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

var rev = "";
var sn = "";
var model = "";
var model2 = "";
var comware = 0;

# 1. check SSH
if ( get_kb_item("Host/HP_Switch/show_modules") )
{
  txt = get_kb_item("Host/HP_Switch/show_modules");
  match = pregmatch(pattern:"Chassis:[ \t]*([^ ]+) ([^ ]+)", string:txt);
  if (!isnull(match))
  {
     model = match[2];
     model2 = match[1];
  }
  match = pregmatch(pattern:"Serial Number:\s+([^ ]+)", string:txt);
  if (!isnull(match)) sn = match[1];
}
if ( get_kb_item("Host/HP_Switch/show_system") )
{
  txt = get_kb_item("Host/HP_Switch/show_system");
  match = pregmatch(pattern:"Software revision[ \t]*:[ \t]*([^ \n\r]+)", string:txt);
  if (!isnull(match)) rev = match[1];
  match = pregmatch(pattern:"Serial Number\s*:\s+([^ ]+)", string:txt);
  if (!isnull(match) && !sn) sn = match[1];
}
if ( get_kb_item("Host/HP_Switch/show_tech") )
{
  txt = get_kb_item("Host/HP_Switch/show_tech");
  match = pregmatch(pattern:"Software revision[ \t]*:[ \t]*([^ \n\r]+)", string:txt);
  if (!isnull(match)) rev = match[1];
  match = pregmatch(pattern:"Serial Number\s*:\s+([^ ]+)", string:txt);
  if (!isnull(match) && !sn) sn = match[1];
  match = pregmatch(pattern:";[ \t]*([^ \n\r]+)[ \t]*Configuration Editor;", string:txt);
  if (!isnull(match) && !model) model = match[1];
}
if ( get_kb_item("Host/HP_Switch/summary") ) # used for Comware systems
{
  txt = get_kb_item("Host/HP_Switch/summary");
  match = pregmatch(pattern:"HPE? ([^ ]+) Switch", string:txt);
  if (!isnull(match))
  {
    if (!model2) model2 = match[1];
    comware++;
  }
  match = pregmatch(pattern:"Comware Software, Version ([0-9][0-9.]+),? Release ([^\s,]+)", string:txt);
  if (!isnull(match))
  {
     if (!rev) rev =  match[1] + " Release " + match[2];
    comware++;
  }
}
if ( get_kb_item("Host/HP_Switch/show_ver") )
{
  txt = get_kb_item("Host/HP_Switch/show_ver");
  temp_array = split(txt);
  foreach var temp_str (temp_array)
  {
    match = pregmatch(pattern:"\s+([A-Z]+\.[0-9]+(\.[0-9]+)*)", string:temp_str);
    if (!isnull(match)) rev = match[1];
    else
    {
      match = pregmatch(pattern:"\s+([A-Z]+[0-9]+(\.[0-9]+)*)", string:temp_str);
      if (!isnull(match)) rev = match[1];
      else
      {
        match = pregmatch(pattern:"\s+([0-9]+\.[0-9]+\.[0-9A-Za-z]+)", string:temp_str);
        if (!isnull(match)) rev = match[1];
      }
    }
  }
}
if ( get_kb_item("Host/OS/showver") )
{
  txt = get_kb_item("Host/OS/showver");
  match = pregmatch(pattern:"HPE? (.*) Switch \((.*)\)(.*)", string:txt);
  if (!isnull(match))
  {
    if (!model) model = match[2];
    if (!model2) model2 = match[1];
    if (match[3] && !rev) rev = match[3] - " with software revision ";
  }
  else
  {
    # match for Comware systems
    match = pregmatch(pattern:"HPE?\s\s*([^\s]+)\s\s*.*Switch\s\s*.*[Vv]ersion,?\s\s*([0-9][0-9.]+)\s\s*[Rr]elease\s\s*([^ ,]+)", string:txt);
    if (!isnull(match))
    {
      if (!model2) model2 = match[1];
      if (match[3] && !rev) rev = match[2] + " Release " + match[3];
      comware++;
    }
  }
}

# 2. check SNMP
if ( (!model) || (!model2) || (!sn) || (!rev) )
{
  community = get_kb_item("SNMP/community");
  if (community)
  {
    port = get_kb_item("SNMP/port");
    if(!port)port = 161;
    if (! get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

    soc = open_sock_udp(port);
    if (soc)
    {
      # validate that we are indeed looking at a HP device
      txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.2.1");
      if (txt)
      {
        match = pregmatch(pattern:"^HPE?\s+[^\s]+\s+Switch", string:txt);
        if (!isnull(match))
        {
          # get hardware model
          if (!model)
          {
            txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.36.1.1.2.5.0");
            if (txt)
            {
              model = txt;
              set_kb_item(name:"SNMP/hardware", value:txt);
            } else {
              # match for Comware systems
              txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.7.1");
              if (txt)
              {
                # HP|HPE V1910-16G Switch JE005A
                match = pregmatch(pattern:"HPE?\s+([^\s]+)\s+Switch\s+(.*)", string:txt);
                if (!isnull(match))
                {
                  model = match[2];
                  if (!model2) model2 = match[1];
                  set_kb_item(name:"SNMP/hardware", value:model);
                  comware++;
                }
              }
            }
          }
          # get serial number
          if (!sn)
          {
            txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.36.1.1.2.9.0");
            if (txt) sn = txt;
            else
            {
              # match for Comware systems
              txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.11.1");
              if (txt)
              {
                sn = txt;
                comware++;
              }
            }
          }
          # get Software version
          if (!rev)
          {
            txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.36.1.1.2.6.0");
            if (txt) rev = txt;
            else
            {
              # match for Comware systems
              # 5.20 Release 1111P02
              txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.7.1");
              if (txt)
              {
                rev = txt;
                comware++;
              }
            }
          }
        }
      }
    }
  }

  if ( (!model) || (!model2) || (!rev) )
  {
    sys = get_kb_item("SNMP/sysDesc");
    if (sys)
    {
      match = pregmatch(pattern:"HPE?\s\s*([^\s]+)\s\s*.*Switch\s\s*([^\s,]+),\s\s*revision\s\s*([^\s,]+)", string:sys);
      if (!isnull(match))
      {
        if (!model) model = match[1];
        if (!model2) model2 = match[2];
        if (!rev) rev = match[3];
      }
      else
      {
        # match for Comware systems, later revsions updated from HP to HPE and added a comma after Version 5.20,
        # HP V1910-16G Switch Software Version 5.20 Release 1111P02
        # HP V1910-16G Switch with Comware software version 5.20 release 1111P02
        match = pregmatch(pattern:"HPE?\s\s*([^\s]+)\s\s*.*Switch\s\s*.*[Vv]ersion\s\s*([0-9][0-9.]+),?\s\s*[Rr]elease\s\s*([^ ,]+)", string:sys);
        if (!isnull(match))
        {
          if (!model2) model2 = match[1];
          if (!rev) rev = match[2] + " Release " + match[3];
          comware++;
        }
      }
    }
  }
}

# if model is not defined but model2 is, then set model = model2
if ( (!model) && (model2) )
{
   model = model2;
   model2 = "";
}

# 3. Exit if no software version was found
if (rev == "") rev = "unknown";
if ( (isnull(rev)) || (!rev) || (rev == "unknown") )
  exit(1, "This is not an HP Switch.");

# 4. Set KBs if found
set_kb_item(name:"Host/HP_Switch/SoftwareRevision", value:rev);
if (isnull (sn) || sn == "") sn = "unknown";
set_kb_item(name:"Host/HP_Switch/SerialNumber", value:sn);
if (isnull(model) || model == "") model = "unknown";
set_kb_item(name:"Host/HP_Switch/Model", value:model);

if ( (! get_kb_item("Host/OS/showver") ) && (model2) )
{
    if (!comware)
      set_kb_item(name:"Host/OS/showver", value:"HP " + model2 + " Switch (" + model + ") with software revision " + rev);
    else
      set_kb_item(name:"Host/OS/showver", value:"HP " + model2 + " Switch with Comware Software version " + rev);

    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"switch");
}

replace_kb_item(name:"Host/HP_Switch", value:TRUE);

if ( (model2) && (model != model2) )  model = model + " (" + model2 + ")";

if (report_verbosity > 0)
{
  report = '\n  Model #           : ' + model +
           '\n  Serial #          : ' + sn +
           '\n  Software revision : ' + rev +
           '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
