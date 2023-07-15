#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70067);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

  script_name(english:"Polycom SIP Detection");
  script_summary(english:"Detects Polycom devices running SIP services.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a VoIP device.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Polycom device based off the listening Polycom
SIP services.");
  script_set_attribute(attribute:"see_also", value:"http://www.polycom.com/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:polycom:hdx_system_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:polycom:soundpoint_ip_301");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:polycom:soundpoint_ip_601");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:polycom:soundpoint_ip_650");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sip_detection.nasl");
  script_require_ports("Services/sip", "Services/udp/sip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Put together a list of all TCP and UDP ports that were identified as
# SIP.
i = 0;
ports = make_list();
foreach proto (make_list("tcp", "udp"))
{
  if (proto == "tcp")
    list = get_kb_list("Services/sip");
  else
    list = get_kb_list("Services/" + proto + "/sip");

  if (empty_or_null(list))
    continue;

  list = make_list(list);
  foreach port (list)
    ports[i++] = make_list(proto, port);
}

if (i == 0)
  audit(AUDIT_HOST_NONE, "SIP services");

# Branch, taking one protocol:port pair each.
pair = branch(ports);
proto = pair[0];
port = pair[1];

if (proto == "tcp")
  banner = get_kb_item("sip/banner/" + port);
else
  banner = get_kb_item("sip/banner/" + proto + "/" + port);

if (empty_or_null(banner)) audit(AUDIT_NO_BANNER, port);

patterns = [
  "^Polycom (ITP|HDX|VSX) ([^(]+) \(Release - (([0-9._]+)-\d+)\)$",
  "^(?:Polycom/[0-9][0-9.]+ )?PolycomVVX-(VVX)_([^-]+)(?:-UA)?/(([0-9][0-9.]+))",
  # PolycomStudioX50/4.0.1-380048
  "^Polycom(Studio)(X[0-9]+)/(([0-9.-]+))$"
];
  
matches = NULL;
foreach pattern (patterns)
{
  matches = pregmatch(string:banner, pattern:pattern);
  if (!isnull(matches)) break;
}
if (isnull(matches)) audit(AUDIT_HOST_NONE, "Polycom SIP services");

kb = "sip/polycom/" + tolower(matches[1]);
pair = proto + "/" + port;
set_kb_item(name:kb, value:pair);
set_kb_item(name:kb + "/" + pair + "/model", value:matches[2]);
set_kb_item(name:kb + "/" + pair + "/full_version", value:matches[3]);
set_kb_item(name:kb + "/" + pair + "/version", value:matches[4]);

report =
  '\nNessus found the following Polycom SIP service :' +
  '\n' +
  '\n  SIP banner : ' + banner +
  '\n  Model      : ' + matches[2] +
  '\n  Version    : ' + matches[3] +
  '\n';

security_note(port:port, protocol:proto, extra:report);
