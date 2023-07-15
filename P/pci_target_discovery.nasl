#
# (C) Tenable Network Security, Inc.
include('compat.inc');

if (description)
{
  script_id(109394);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_name(english:"WAS Target Scanning for PCI");
  script_summary(english:"Report www ports and protocol.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin reports http addresses for http and https pages of a scanned system.");
  script_set_attribute(attribute:"description", value:
"This plugin reports http addresses for http and https pages of a
scanned system.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_dependencies("dont_scan_printers.nasl", "dont_scan_printers2.nasl", "dont_scan_ot.nasl", "pci_was_websites.nasl");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Host/dead");
  exit(0);
}

include('global_settings.inc');
include('audit.inc');

# skip checking this in command line mode so flatline tests will work
if (!isnull(get_preference("plugins_folder")))
{
  var policy_name = get_preference("@internal@policy_name");
  if(policy_name != "PCI Discovery")
    exit(0, "This plugin only runs under the PCI discovery policy.");
}

if (!get_kb_item("Settings/PCI_DSS"))
  audit(AUDIT_PCI);

if(get_kb_item("Host/dead"))
  audit(AUDIT_HOST_NOT, "alive or was excluded from scanning by policy.");

# Amass the list of http and https addresses
var www_kbs = get_kb_list_or_exit("PCI_WAS_www/*");
var port_pattern = "PCI_WAS_www\/([0-9]+)$";

var scan_target = get_host_name();
if (get_kb_item("PCI/target_discovery/test_mode")) scan_target = "127.0.0.1";
var was_targets = make_list();

www_kbs = list_uniq(sort(keys(www_kbs)));

var www_key, port_match, protos, proto, port;
for(i = 0; i < max_index(www_kbs); i++)
{
  www_key = www_kbs[i];
  port_match = pregmatch(string:www_key, pattern:port_pattern);
  if (!isnull(port_match) && len(port_match) > 1)
  {
    protos = get_kb_list(www_key);
    foreach proto(protos)
    {
      port = port_match[1];
      was_targets = make_list(was_targets, proto + "://" + scan_target + ':' + port);
    }
  }
}

# Report xml tags
report_xml_tag(tag:"nessus_targets", value:scan_target);
set_kb_item(name:"PCI/target_discovery/nessus_targets", value:scan_target);
var report_data = '';

var report_data, was_targets_stringified;
if (!empty_or_null(was_targets))
{
  report_data += '\nWAS Scan Target List:\n\n';
  was_targets_stringified = join( was_targets, sep:'\n' );
  report_data += was_targets_stringified;
  report_xml_tag(tag:"was_targets", value:was_targets_stringified);
  replace_kb_item(name:"PCI/target_discovery/was_targets", value:was_targets_stringified);
}

if(report_data != '')
  security_note(port:0, data:report_data);
else
  exit(0, "No WAS scan targets found.");

