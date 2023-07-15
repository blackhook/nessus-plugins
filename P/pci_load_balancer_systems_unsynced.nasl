#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109582);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/04 10:19:47");

  script_name(english:"PCI Scan Accuracy cannot be verified through Load Balancer with non-identically configured or non-synced systems");
  script_summary(english:"The remote has is behind a load balancer either with a non-identical configurations to its peers, or is not synced with its peers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote has is behind a load balancer either with a non-identical
configurations to its peers, or is not synced with its peers.");
  script_set_attribute(attribute:"description", value:
"The remote has is behind a load balancer either with a non-identical
configurations to its peers, or is not synced with its peers.");
  script_set_attribute(attribute:"solution", value:
"Configure the remote peers identically or syc them to each other.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/04");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_SETTINGS);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Settings/PCI_DSS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Settings/PCI_DSS"))
  audit(AUDIT_PCI);

# skip checking this in command line mode so flatline tests will work
if (!isnull(get_preference("plugins_folder")))
{
  policy_name = get_preference("@internal@policy_name");
  if(policy_name != "PCI Discovery")
    exit(0, "This plugin only runs under the PCI discovery policy.");
}

unsync_warning = 'Note to customer: As you were unable to validate that the configuration of the\n' +
                 'environment behind your load balancers is synchronized, it is your\n' +
                 'responsibility to ensure that the environment is scanned as part of the internal\n' +
                 'vulnerability scans required by the PCI DSS.';
sync_status = get_preference("Load balancer[radio]:Load Balancer Synced");

if (sync_status == "Unsynced")
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : unsync_warning
  );

}
else
{
  exit(0, "The remote system is not behind a load balancer or is synced and identically configured. Status: " + sync_status);
}
