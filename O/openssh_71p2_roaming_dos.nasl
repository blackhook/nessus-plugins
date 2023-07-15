#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(106608);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_bugtraq_id(80695, 80698);

  script_name(english:"OpenSSH 5.4 < 7.1p2 Multiple Vulnerabilities");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is 5.x, 6.x or 7.x prior to 7.1p2. It is, therefore, affected by 
multiple vulnerabilities. 

  - A potential information disclosure vulnerability which
    may allow remote servers to obtain sensitive information 
    from process memory by requesting transmission of an
    entire buffer (CVE-2016-0777)

  - A denial of service vulnerability due to a heap-base
    overflow in roaming_common.c (CVE-2016-07778)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.1p2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.1p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "OpenSSH";

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = tolower(get_kb_item_or_exit("SSH/banner/"+port));

# Ensure target is openssh
if ("openssh" >!< banner) audit(AUDIT_NOT_LISTEN, app_name, port);

# Paranoid scans only
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get the version in the backported banner.
v_match = pregmatch(string:banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(v_match)) audit(AUDIT_SERVICE_VER_FAIL, app_name, port);
version = v_match[1];

# Granularity check
if (version =~ "^[57]$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

# Vuln branches checkV
if (version !~ "^[567]($|[^0-9])")
  audit(AUDIT_NOT_LISTEN, app_name + " 5.x / 6.x / or 7.x", port);

if (
  # 5.4 < 6
  version =~ "^5\.[4-9]($|[^0-9])" ||
  # 6.0
  version =~ "^6\.[0-9]($|[^0-9])" ||
  # 7.0
  version =~ "^7\.0($|[^0-9])" ||
  # 7.1
  version == "7.1" ||
  # 7.1p1
  version =~ "^7\.1p[01]($|[^0-9])"
)
{
  security_report_v4(
    port     : port,
    severity : SECURITY_WARNING,
    extra    :
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.1p2\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
