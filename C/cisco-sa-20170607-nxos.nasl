#TRUSTED 6bbb090bdc42cac064ba967b8e9e8d79c76cde5997f7f3eed334c49b243544990318cc3e46b102933a7eb2498569b314431d012fbb3d7595c8e6ee17cd86c0aeb1f307fca0e2dc8ffc61477627098c319ae036c93df4db74e465e95c468ade60a9078f149ded4e756329d18bdc3c2d5e31eaf1820ac767c5642ddd8f77c6864ff1f1c5c18959019645a15f43a76fba53ce2e77a0a1c11e77376340db68a795894671607784d8e0116393569d8e2174e7a394bc40ff69686105139c1cce278c9c7ef67fe0aff989c1840ac383d1be455cb7b955e2ac7de008560e975e32ecbf2e133f3385775a387e6c1b8c985474601c5d10e0e044a832213c28e08ceedc6fc7563f17da0bde3dadf5d99a29a48f5a67bbbeb8db2ea0d25cbb754a1a510ed39954098b600c15fcb5c46f3ce1c6f2cc40a6005212079f964abf3d005605602e7285b35696b6a63e9bd1e70da306386943911b9d747fbd394d3b6a806d43e0fb7ed10c933dd4ae6c6e0691e75a52369ea2736e7d5878a3ea7370fba253564b024ae9ce4fcad7635a0e08723637fc5d667dc1d2b1d7a59ef5a8bfef7b69e0f0470763f99dc8eebf02e5ea618e8fe75b4f310355cf95fa4fd6fa0b1475927824df0b8e29f76330cdfc8c805378367c135e7d76febed7575c36e68c69ada08e1a758959290194429a3d23598a5f63fec0884103e2ff980da7676a34fd99c1367431d2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100840);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-6655");
  script_bugtraq_id(98991);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc91729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170607-nxos");
  script_xref(name:"IAVB", value:"2017-B-0072");

  script_name(english:"Cisco NX-OS Fibre Channel over Ethernet DoS (cisco-sa-20170607-nxos)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the Fibre Channel over Ethernet (FCoE) protocol
implementation due to improper padding validation of FCoE frames. An
unauthenticated, adjacent attacker can exploit this, via a stream of
specially crafted FCoE packets, to cause an FCoE-related process to
unexpectedly reload, thereby impacting FCoE traffic passing through
the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-nxos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e150b33");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc91729");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvc91729.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

flag = FALSE;
cbid = "CSCvc91729";

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

# 7000 series
if (model =~ "^7[0-9][0-9][0-9]([^0-9]|$)")
{
  if (version == "8.0(1)S2" || version == "8.3(0)CV(0.833)")
    flag = TRUE;
}

# 7700 series
if (model =~ "^77[0-9][0-9]([^0-9]|$)")
{
  if (version == "8.0(1)(ED)")
    flag = TRUE;
}

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # check if fcoe is enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show feature-set fcoe", "show feature-set fcoe");
  if (check_cisco_result(buf))
  {
    if ("enabled" >< buf)
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_NOTE,
    override : override,
    version  : version,
    bug_id   : cbid
  );
}
else audit(AUDIT_HOST_NOT, "affected");
