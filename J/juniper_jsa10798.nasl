#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102073);
  script_version ("1.4");
  script_cvs_date("Date: 2018/07/13 15:08:46");

  script_cve_id("CVE-2016-3074");
  script_bugtraq_id(87087);
  script_xref(name:"JSA", value:"JSA10798");
  script_xref(name:"EDB-ID", value:"39736");

  script_name(english:"Juniper Junos libgd Compressed GD2 Data RCE (JSA10798)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by an integer signedness error in the
included GD Graphics Library (libgd) when handling compressed GD2 data
due to improper validation of user-supplied input. An unauthenticated,
remote attacker can exploit this, via specially crafted compressed GD2
data, to cause a heap-based buffer overflow, resulting in a denial of
service condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10798");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10798.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['12.1X46'] = '12.1X46-D65';
fixes['12.3X48'] = '12.3X48-D40';
fixes['14.2']    = '14.2R8';
fixes['15.1']    = '15.1R5';
fixes['15.1X49'] = '15.1X49-D70';
fixes['15.1X53'] = '15.1X53-D47';
fixes['16.1']    = '16.1R4';
fixes['16.2']    = '16.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, severity:SECURITY_HOLE);
