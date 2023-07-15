#
# (C) Tenable Network Security, Inc.
#
# Disabled on 2018/08/14. Re-enabled on 2020/10/26. 

include("compat.inc");

if (description)
{
  script_id(102425);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_name(english:"Active Inbound Connection From Host Listed in Custom Netstat IP Threat List");
  script_summary(english:"Uses results of nbin to report inbound custom ipthreat connections.");

  script_set_attribute(attribute:"synopsis", value:
"According to a custom netstat IP threat list, the remote host is
making an inbound connection to a host that is listed as a threat.");
  script_set_attribute(attribute:"description", value:
"According to the output from netstat, the remote host has an inbound
connection to one or more hosts that are listed in the custom netstat
IP threat list.");
  script_set_attribute(attribute:"solution", value:
"Determine which services the hosts are connected to, and
investigate further if necessary.");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");

  script_dependencies("ipthreat_lookup_netstat_custom.nbin");
  script_require_keys("ipthreat/lookup/custom/inbound");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

data_protection::disable_plugin_if_set(flags:make_list(data_protection::DPKB_IPADDR));

report = get_kb_item_or_exit("ipthreat/lookup/custom/inbound");
security_note(port:0, extra:report);
