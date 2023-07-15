		#
# Custom plugin
# Checks the OUI to determine device type.
#

include("compat.inc");

if (description)
{
  script_id(102821);
  script_version("2.8");
  script_cvs_date("Date: 2020/01/22");

  script_name(english:"OS Identification : OUI");
  script_summary(english:"Determines the remote operating system");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the
response from the OUI.");
  script_set_attribute(attribute:"description", value:
"This script attempts to identify the operating system type and
version by looking at the data returned by OUI");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ethernet_manufacturer.nasl");
  script_require_keys("Host/ethernet_manufacturer/Enumerated");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("Host/ethernet_manufacturer/Enumerated");

# Get KB list and count per manufacturer
manufacturers = get_kb_list_or_exit("Host/ethernet_manufacturer/macs/*");

# since there may be multiple interfaces made by different manufacturers...
results = make_array();
foreach maker (manufacturers)
{
  results[maker]++;
}


# ...Find the most common
high_count = 0;
high_name = NULL;
foreach m (alpha_sort(keys(results)))
{
  if (results[m] > high_count)
  {
    high_count = results[m];
    high_maker = m;
  }
}

report = "Ethernet interfaces associated with " + high_maker;

white_list = make_list(
  "Nest Labs Inc.",
  "NetApp",
  "Nintendo",
  "Sony Computer Entertainment",
  "Sony Interactive Entertainment Inc."
);


eth_conf = 90;

foreach vendor (white_list)
{
  if (vendor >< high_maker)
  {
    maker_disclaimer = "an operating system associated with " + high_maker;

    set_kb_item(name:"Host/OS/Ethernet", value:maker_disclaimer);
    set_kb_item(name:"Host/OS/Ethernet/Confidence", value:eth_conf);
    set_kb_item(name:"Host/OS/Ethernet/Type", value:"embedded");

    security_note(port: 0, extra: '\n'+report);
  }
}








