#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55934);
  script_version("1.9");
  script_cvs_date("Date: 2018/08/10 18:07:07");

  script_name(english:"Juniper Junos Extended DHCP Relay Agent Traffic Redirection (PSN-2011-07-300)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote router allows traffic redirection."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Juniper
router has a vulnerable Extended DHCP Relay Agent.  Any
interface which has the Extended DHCP Relay Agent enabled
intercepts unicast DHCP reply packets.  A remote attacker could
exploit this by acting as a malicious DHCP server, sending
specially crafted unicast DHCP reply packets through the router.
This could result in traffic being redirected."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4d1c392");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2011-07-300."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

fixes['10.0'] = '10.0R4';
fixes['10.1'] = '10.1R3';
fixes['10.2'] = '10.2R2';
fixes['10.3'] = '10.3R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:MX_SERIES | M_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_note(port:0, extra:report);
}
else security_note(0);

