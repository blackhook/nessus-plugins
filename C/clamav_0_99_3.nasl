#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106610);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/06 11:26:07");
  script_cve_id(
    "CVE-2017-12374",
    "CVE-2017-12375",
    "CVE-2017-12376",
    "CVE-2017-12377",
    "CVE-2017-12378",
    "CVE-2017-12379",
    "CVE-2017-12380"
  );

  script_name(english:"ClamAV < 0.99.3 Multiple libclamav DoS");
  script_summary(english:"Checks the response to a clamd VERSION command.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus service running on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon running on
the remote host is prior to 0.99.3. It is, therefore, affected by
multiple vulnerabilities - one, which expose the system to a DoS 
attack and another, which provides potential adversaries with Remote 
Code Execution capabilities.
");
  script_set_attribute(attribute:"see_also", value:"http://blog.clamav.net/2018/01/clamav-0993-has-been-released.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.clamav.net/pipermail/clamav-announce/2018/000027.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV version 0.99.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port    = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^0\.(\d|[0-8]\d|9[0-8])($|[^0-9])"
  ||
  version =~ "^0.99($|-beta[12]|-rc[12])"
  ||
  version =~ "^0\.99\.[012]($|[^0-9])"
)
{
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.99.3' +
      '\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
