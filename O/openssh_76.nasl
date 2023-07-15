#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103781);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-15906");
  script_bugtraq_id(101552);

  script_name(english:"OpenSSH < 7.6");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a 
file creation restriction bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.6. It is, therefore, affected by a file creation
restriction bypass vulnerability related to the 'process_open'
function in the file 'sftp-server.c' that allows authenticated users
to create zero-length files regardless of configuration.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://github.com/openbsd/src/commit/a6981567e8e215acc1ef690c8dbb30f2d9b00a19#diff-8b99aa649abd796be7cc465d6f0a2f96
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09ca048b");
  # https://github.com/openssh/openssh-portable/commit/4d827f0d75a53d3952288ab882efbddea7ffadfe#diff-066c02faff81900a14a658dae29b3e15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96a8ea52");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/" + port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner)
  audit(AUDIT_NOT_LISTEN, "OpenSSH", port);
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);
if (backported)
  audit(code:0, AUDIT_BACKPORT_SERVICE, port, "OpenSSH");

# Check the version in the backported banner.
match = pregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match))
  audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

fix = "7.6";
if (
  version =~ "^[0-6]\." ||
  version =~ "^7\.[0-5](p[0-9])?$"
   )
{
  items = make_array("Version source", banner,
                     "Installed version", version,
                     "Fixed version", fix);
  order = make_list("Version source", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
