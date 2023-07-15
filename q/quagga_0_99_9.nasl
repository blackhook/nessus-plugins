#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59795);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:23");

  script_cve_id("CVE-2007-4826");
  script_bugtraq_id(25634);

  script_name(english:"Quagga < 0.99.9 BGPD Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Check the version of Quagga");

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Quagga's BGP daemon listening on the remote host is affected by
multiple denial of service vulnerabilities :

  - A denial of service vulnerability can be triggered by a
    malformed OPEN message from an explicitly configured BGP
    peer.

  - A denial of service vulnerability can be triggered by a
    malformed COMMUNITY attribute from an explicitly
    configured BGP peer, when the daemon has debugging
    enabled.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.99.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20100629152435/http://www.quagga.net/download/attic/quagga-0.99.9.changelog.txt");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:quagga:quagga");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("quagga_zebra_detect.nasl");
  script_require_keys("Quagga/Installed", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Quagga Zebra";
kb = "Quagga/";

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_kb_item_or_exit(kb + "Installed");

kb += port + "/";
banner = get_kb_item_or_exit(kb + "Banner");
ver = get_kb_item_or_exit(kb + "Version");

if (ver !~ "^\d+(\.\d+)*$")
  audit(AUDIT_NONNUMERIC_VER, app, port, ver);

fix = "0.99.9";
if (ver_compare(ver:ver, fix:fix, strict:TRUE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_note(port:port, extra:report);
