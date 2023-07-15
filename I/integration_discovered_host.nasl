#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168417);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_name(english:"Integration Discovered Host");

  script_set_attribute(attribute:"synopsis", value:
"This host was discovered by an integration and added to the scan.");
  script_set_attribute(attribute:"description", value:
"This host was discovered by an integration and added to the scan. This plugin 
reports which integration discovered this host and added it to the scan. 
Please see specific integration configuration for more details.");
  script_set_attribute(attribute:"solution", value: "NA");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("host/injected/integration");

  exit(0);
}

var injected_integration = get_kb_item("host/injected/integration");

var report = "This host was injected by the integration " + injected_integration + '.';

security_report_v4(
    port:0, 
    extra:report,
    severity: 0
);
