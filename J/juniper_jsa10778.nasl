#TRUSTED 5b9bf7aa0b98e9faf60caf8adf90a136e0cbd3d2e6a0e6b99b395eda8be20ea679ec40bac7cd86506c9921c0bb2bbc762457716957794532d7a93b4906b28b29fceeb330fcd8641f1f8ff723a35cc804eb003d420112df680d4cf0c56baead3c27066af5488c38ae2a12776a66ec1fb23b507b861b768113ea4062a5c88f7f4b44f731484bfb8d0d4da816d923985a51cec1885ecae60be7219ee4e24a2090db33c3f9ac62c852478ce7f09379b4ccbc20c38ec8ea34bf39b572f67fef84bf3886a5035b1de54a5b55d7c78db8eb74ece544c87aa68916db9d236e292b0cdba751296b373b3d56fc77f3f257412ab7366f40325748de41c06ba3bda16aece7567b35bf74d0104b68665196057bf208c263738d5fc94c63cff2732cd9634ef123e4c06efb01b08e6c9f82108b4e988abf8bceea65bb8ca52ceef2c9d1ca37e5cb618abf0c10d0a2b63a1bc0d9875c33cacab8226a38e519a53c8b432234c1eb5f7c740001c9852e227311c02e51b05a2b25207c024a086691e1da39a9a8efa6cb1bfc8936ea854f0dc4a51263f8a19d1b56c315a79063fca067d3230b366aaa1927922ed499aeb7bb09ea6e1925e6aac38a1e0ebc0ad7ea2d5fa851b61923d51707d644e96c5f276d5a22850f5f73cf12aae4cdc79ad65132cc6f284781160aa7d7b1b86429482dbcb1e101e08c601576410be7b2e57e9dc23efc18e957b02b21
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99525);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2313");
  script_bugtraq_id(97606);
  script_xref(name:"JSA", value:"JSA10778");

  script_name(english:"Juniper Junos Routing Process Daemon BGP UPDATE DoS (JSA10778)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the remote
Juniper Junos device is affected by a denial of service vulnerability
in the routing protocol daemon (rpd) when handling a specially crafted
BGP UPDATE. An unauthenticated, remote attacker can exploit this to
repeatedly crash and restart the rpd daemon.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10778&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?910a6d37");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10778.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
# Commands ran may not be available on all models
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['15.1F2'] = '15.1F2-S15';
fixes['15.1F5'] = '15.1F5-S7';
fixes['15.1F6'] = '15.1F6-S5';
fixes['15.1F'] = '15.1F7';
fixes['15.1R4'] = '15.1R4-S7';
fixes['15.1R5'] = '15.1R5-S2';
fixes['15.1R'] = '15.1R6';
fixes['15.1X49'] = '15.1X49-D78'; # or 15.1X49-D80
fixes['15.1X53'] = '15.1X53-D63'; # or 15.1X53-D70 or 15.1X53-D230
fixes['16.1R3'] = '16.1R3-S3';
fixes['16.1'] = '16.1R4';
fixes['16.2R1'] = '16.2R1-S3';
fixes['16.2'] = '16.2R2';
fixes['17.1'] = '17.1R1';
fixes['17.2'] = '17.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show bgp neighbor");
if (buf)
{
  if (preg(string:buf, pattern:"BGP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP is not enabled"); 
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
