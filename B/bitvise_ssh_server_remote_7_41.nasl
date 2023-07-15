#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110291);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_xref(name:"IAVB", value:"2018-B-0068-S");

  script_name(english:"Bitvise SSH Server < 7.41 Multiple Vulnerabilities (remote)");
  script_summary(english:"Checks the Bitvise SSH Server banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bitvise SSH Server running on
the remote host is prior to 7.41. It is, therefore, affected by
multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
 # https://www.bitvise.com/flowssh-version-history#security-notification-741
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bf2994b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Bitvise SSH Server 7.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitvise:ssh_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
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

# SSH-2.0-7.36 FlowSsh: Bitvise SSH Server (WinSSHD) 7.39
if ("Bitvise SSH Server (WinSSHD)" >!< banner)
  audit(AUDIT_NOT_LISTEN, "Bitvise SSH Server (WinSSHD)", port);

# Check the version in the banner.
match = pregmatch(string:banner, pattern:"Bitvise SSH Server \(WinSSHD\) ([0-9.]+)$");
if (isnull(match))
  audit(AUDIT_SERVICE_VER_FAIL, "Bitvise SSH Server (WinSSHD)", port);
version = match[1];

fix = "7.41";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  items = make_array("Version source", banner,
                     "Installed version", version,
                     "Fixed version", fix);
  order = make_list("Version source", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Bitvise SSH Server (WinSSHD)", port, version);
