#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76936);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2014-3537");
  script_bugtraq_id(68788);

  script_name(english:"CUPS 1.7.x < 1.7.4 'get_file' Function Symlink Handling Info Disclosure");
  script_summary(english:"Checks the CUPS server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote print service is potentially affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is 1.7.x prior to 1.7.4. It is, therefore, potentially affected
by an information disclosure vulnerability.

A flaw exists in the 'get_file' function within the file
'scheduler/client.c' regarding the handling of symlinks. This could
allow a local attacker to cause normally protected files to be
accessible via the web interface.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cups.org/blog/2014-07-14-cups-1.7.4.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apple/cups/issues/4450");
  script_set_attribute(attribute:"see_also", value:"https://cups.org/strfiles.php/3363/str4450.patch");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to CUPS version 1.7.4 or later, or apply the vendor
patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3537");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "cups_1_3_5.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);
get_kb_item_or_exit("www/"+port+"/cups/running");

version = get_kb_item_or_exit("cups/"+port+"/version");
source  = get_kb_item_or_exit("cups/"+port+"/source");

if (version =~ "^(1|1\.7)($|[^0-9br.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected :
# 1.7.x < 1.7.4
if (
  version =~ "^1\.7\.[0-3]($|[^0-9.])" ||
  version =~ "^1\.7(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.7.4' +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
