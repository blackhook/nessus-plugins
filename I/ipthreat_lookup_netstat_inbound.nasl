#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/08/14. Disabling threat feed plugins till feed is resolved.

include("compat.inc");

if (description)
{
  script_id(59713);
  script_version("1.7");
  script_cvs_date("Date: 2018/08/14 15:49:28");

  script_name(english:"Active Inbound Connection From Host Listed in Known Bot Database");
  script_summary(english:"Uses results of nbin to report inbound botnet connections");

  script_set_attribute(
    attribute:"synopsis",
    value:
"According to a third-party database, the remote host is receiving an
inbound connection from a host that is listed as part of a botnet."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This plugin has been temporarily disabled.

According to the output from netstat, the remote host has an inbound
connection from one or more hosts that are listed in a public database
as part of a botnet."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Determine which services the botnet hosts are connected to, and
investigate further if necessary."
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/06/26");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("ipthreat_lookup_netstat.nbin");
  script_require_keys("botnet_traffic/inbound/report");

  exit(0);
}

exit(0, "This plugin has been temporarily disabled.");

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

data_protection::disable_plugin_if_set(flags:make_list(data_protection::DPKB_IPADDR));

report = get_kb_item_or_exit('botnet_traffic/inbound/report');
security_note(port:0, extra:report);
