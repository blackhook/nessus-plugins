#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102074);
  script_version ("1.4");
  script_cvs_date("Date: 2018/07/13 15:08:46");

  script_cve_id("CVE-2017-3135");
  script_bugtraq_id(96150);
  script_xref(name:"JSA", value:"JSA10799");

  script_name(english:"Juniper Junos SRX, vSRX, and J-Series ISC BIND DoS (JSA10799)");
  script_summary(english:"Checks the Junos version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Juniper Junos device is affected by a denial of service vulnerability
in ISC BIND, specifically in the query_find() function within file
bin/named/query.c, when simultaneously using DNS64 and RPZ for query
responses. An unauthenticated, remote attacker can exploit this to
cause an INSIST assertion failure or a NULL pointer read, resulting in
termination of the service.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10799");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10799.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^(J|v?SRX)")
  audit(AUDIT_HOST_NOT, 'a J or SRX or vSRX device');

fixes = make_array();

fixes['12.1X46'] = '12.1X46-D67';
fixes['12.3X48'] = '12.3X48-D50';
fixes['15.1X49'] = '15.1X49-D80';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_HOLE);
