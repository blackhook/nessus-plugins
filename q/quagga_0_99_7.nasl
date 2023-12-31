#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59794);
  script_version("1.8");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2007-1995");
  script_bugtraq_id(23417);

  script_name(english:"Quagga < 0.98.7 / 0.99.7 BGPD Denial of Service Vulnerability");
  script_summary(english:"Check the version of Quagga");

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Quagga's BGP daemon listening on the remote host is affected by a
denial of service vulnerability. The issue can be triggered by a
specially crafted UPDATE message from an explicitly configured BGP
peer.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.quagga.net/show_bug.cgi?id=354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.quagga.net/show_bug.cgi?id=355");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20100629132657/http://www.quagga.net/download/attic/quagga-0.99.7.changelog.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.98.7 / 0.99.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1995");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:quagga:quagga");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (version =~ "^0\.98([^0-9]|$)")
  fix = "0.98.7";
else
  fix = "0.99.7";

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

security_warning(port:port, extra:report);
