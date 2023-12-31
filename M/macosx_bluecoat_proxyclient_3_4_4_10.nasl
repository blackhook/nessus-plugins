#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93404);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2015-1454");
  script_bugtraq_id(73150);
  script_xref(name:"IAVA", value:"2016-A-0227");

  script_name(english:"Blue Coat ProxyClient < 3.3.3.3 / 3.4.x < 3.4.4.10 Certificate Validation MitM");
  script_summary(english:"Checks the version of ProxyClient.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a
man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Blue Coat ProxyClient installed on the remote Windows
host is either prior to 3.3.3.3 or is 3.4.x prior to 3.4.4.10. It is,
therefore, affected by a man-in-the-middle (MitM) vulnerability due to
improper validation of the Client Manager certificate. A MitM attacker
can exploit this, via a specially crafted certificate, to spoof
ProxySG Client Managers, allowing the attacker to modify
configurations and execute arbitrary software updates.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa89");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Blue Coat ProxyClient version 3.3.3.3 / 3.4.4.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bluecoat:proxyclient");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_bluecoat_proxyclient_installed.nbin");
  script_require_keys("installed_sw/ProxyClientUI");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'ProxyClientUI';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

if (version =~ '^3\\.4\\.')
  fix = '3.4.4.10';
else
  fix = '3.3.3.3';

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version);
