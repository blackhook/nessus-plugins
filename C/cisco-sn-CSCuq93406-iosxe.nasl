#TRUSTED 482d642216215faba881a92b713ad8d0d12885d2ff592bf5dac4eb92e00af4f5fd9e28c1bbd425d6ade14fcc1b25f63465ef2f300491a4362e2e8f86f02797160cce056af0101afebb0132b171f8cdc67d99a4387cf1d8045981ea2f4c5595c55d0c7b36d22100ba25bf734e285d616e82239581268f15d64cb336d4f53880a08ad4f6652802e503c17a859547ddaf4423e02964c6f6430c426c88bc376fe4339700f44e0d3d71bf74af3b136b6652b56bc694ca5b4bba56a8a4b74d7a5a6b06f7bc39212a90e3f37f66eed40e990f25dff06cc8f3d56b791dd4c974f2a01cd7459c911b19137574ab7893ca88c13fba4b2dd63408850bc08dea697c97ed0867c62e6be59fba3c6a916b3b5649f3920e715287dcecfe1ed1fbdb5e2341955d9e42873754ac8d64a065f99bf49e0050aa455b77c4540d0f6b54a7e99df844e8c8bc3ef02bb7351b206fce645fa3197842125815c4b48a728b8f536df68e0c173bda8ff3019ae2fe692475777b42e4ec0c2dea2798d917a18838a7cd6ea0c1be2f3399302475ef368b5616365cf525eda6168cff49bb090acfdf6f255db2bb0cbf25e50386d1f64f5a702d39003f9eaff7c3dc518eb3e627ecdadb8bf65db6ac6543a7af69d13fa9a32020821720091f6e1923f782d5841c1fa5f4a7060cf35d2e1ce6a49a83855163611bd1cbeb13d72f86358906d762caa70661f15e05e66a09
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78919);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3409");
  script_bugtraq_id(70715);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq93406");

  script_name(english:"Cisco IOS XE Software Connectivity Fault Management (CFM) DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is affected by a denial of service
vulnerability due to due to improper parsing of malformed Ethernet
Connectivity Fault Management (CFM) packets. A remote, unauthenticated
attacker, using specially crafted CFM packets, could trigger a denial
of service condition, resulting in a reload of the device.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=36184
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8080ca42");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Notice.

Alternatively, disable Ethernet Connectivity Fault Management (CFM).");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check model
model = get_kb_item("Host/Cisco/IOS-XE/Model");

if (!model)
{
  # If no model, just do ver checks per Alert page
  # 3.1S .0, .1, .2, .3
  if (version =~ "^3\.1\.[0-3]S$") flag++;
  # 3.2S .0, .1, .2
  else if (version =~ "^3\.2\.[0-2]S$") flag++;
  # 3.3S .0, .1, .2
  else if (version =~ "^3\.3\.[0-2]S$") flag++;
  # 3.4S .0, .1, .2, .3, .4, .5, .6
  else if (version =~ "^3\.4\.[0-6]S$") flag++;
  # 3.5S Base, .0, .1, .2
  # 3.6S Base, .0, .1, .2
  # 3.7S Base, .0, .1, .2, .3, .4, .5, .6
  else if (version =~ "^3\.[5-7]S$") flag++;
  else if (version =~ "^3\.[5-7]\.[0-2]S$") flag++;
  else if (version =~ "^3\.7\.[4-6]S$") flag++;
  # 3.9S .0, .1, .2
  else if (version =~ "^3\.9\.[0-2]S$") flag++;
  # 3.10S .0, .0a, .1, .2, .3, .4
  else if (version =~ "^3\.10\.(0a|[0-4])S$") flag++;
  # 3.11S .1, .2
  else if (version =~ "^3\.11\.[0-2]S$") flag++;
  # 3.12S .0
  else if (version == '3.12.0S') flag++;
  # 3.13S .0
  else if (version == '3.13.0S') flag++;
}
else
{
  # If model is present, do ver check per model per Bug page note
  if ('ASR901' >< model && version =~ "^3\.3\.") flag++;
  else if ('ASR903' >< model && version =~ "^3\.5\.") flag++;
  else if ('ASR920' >< model && version =~ "^3\.13\.") flag++;
  else if (('ASR1k' >< model || model =~ '^ASR 10[0-9][0-9]($|[^0-9])') && version =~ "^3\.2\.") flag++;
}

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"ethernet cfm", string:buf)) flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuq93406' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
