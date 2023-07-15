#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111206);
  script_version("1.2");
  script_cvs_date("Date: 2018/12/21 12:29:53");

  script_cve_id("CVE-2018-0026");
  script_bugtraq_id(104720);
  script_xref(name:"JSA", value:"JSA10859");

  script_name(english:"Juniper Junos Security Bypass Stateless Firewall Deactivation (JSA10859)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a firewall deactivation on reboot vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10859
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?075586cf");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10859.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0026");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

# 15.1R4, 15.1R5, 15.1R6 and SRs based on these MRs.
# 15.1X8 versions prior to 15.1X8.3.
# Note:
#   No prior mention of a version that matches \d{1,2}\.\dX\d{1,2}\.\d
#   i.e. no version with a full stop in version after X
#   Normally: 15.1X49-D70 (This is what junos.inc handles)
#   Update junos.inc upon confirmation of new version pattern

fixes = make_array();
if (ver =~ "^15\.1R[4-6]($|[^0-9])") fixes['15.1R'] = '15.1R7';
# fixes['15.1X8'] = '';     # Placeholder.

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
