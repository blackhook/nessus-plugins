#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109211);
  script_version("1.2");
  script_cvs_date("Date: 2018/07/26 18:36:16");

  script_cve_id("CVE-2018-0017");
  script_bugtraq_id(103749);
  script_xref(name:"JSA", value:"JSA10845");

  script_name(english:"Juniper Junos VPLS Routing MPLS Packet Handling mbuf Exhaustion Remote DoS (JSA10845)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10845&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b3ea034");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10845.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

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

if (model !~ '^SRX')
  audit(AUDIT_HOST_NOT, 'an SRX model');

# Affected:
# 12.1X46 versions prior to 12.1X46-D76
# 12.3X48 versions prior to 12.3X48-D55
# 15.1X49 versions prior to 15.1X49-D90

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D76';
fixes['12.3X48'] = '12.3X48-D55';
fixes['15.1X49'] = '15.1X49-D90';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
