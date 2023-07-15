#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103701);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12166");
  script_xref(name:"IAVA", value:"2017-A-0285");

  script_name(english:"OpenVPN 2.x < 2.3. 18/ 2.4.x < 2.4.4 Buffer Overflow Vulnerability w/ key-method 1");
  script_summary(english:"Checks the OpenVPN version.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a bufferoverflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN
installed on the remote host is affected by an error related to
a weakness in the 'key-method 1' implementation which could allow
buffer overflow attacks and result in unexpected code execution");
  # https://community.openvpn.net/openvpn/wiki/CVE-2017-12166
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1972657");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN 2.3.18 / 2.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openvpn_installed.nbin");
  script_require_keys("installed_sw/OpenVPN");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "OpenVPN";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

if (version =~ "^2(\.[34])?$") audit(AUDIT_VER_NOT_GRANULAR, "OpenVPN", version);

vuln = NULL;
item = pregmatch(pattern:"^(((\d+\.)*)?(\d+))\.?($|[^\d])", string:version);
version = item[1];

if(version =~ "2\.4($|\.)" && ver_compare(ver:version, fix:"2.4.4", strict:FALSE) == -1)
  vuln = TRUE;
else if(ver_compare(ver:version, fix:"2.3.18", strict:FALSE) == -1)
  vuln = TRUE;

if (vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

    report = '\n  Path              : ' + path +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 2.3.18 / 2.4.4' +
             '\n';
    security_report_v4(port:port, severity: SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "OpenVPN", version, path);
