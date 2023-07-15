#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93051);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2016-5332");
  script_bugtraq_id(92448);
  script_xref(name:"VMSA", value:"2016-0011");

  script_name(english:"VMware vRealize Log Insight 2.x / 3.x < 3.6.0 Directory Traversal File Disclosure (VMSA-2016-0011)");
  script_summary(english:"Checks the version of VMware vRealize Log Insight.");

  script_set_attribute(attribute:"synopsis", value:
"A log management application running on the remote host is affected by
a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware vRealize Log Insight application running on the remote host
is 2.x or 3.x prior to 3.6.0. It is, therefore, affected by a
directory traversal vulnerability due to improper sanitization of
user-supplied input. An unauthenticated, remote attacker can exploit
this to disclose arbitrary files.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0011.html");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2016/Aug/49");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Log Insight version 3.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/19");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_log_insight");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_log_insight_webui_detect.nbin");
  script_require_ports("installed_sw/VMware vRealize Log Insight");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

app = "VMware vRealize Log Insight";
fix = "3.6.0";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, embedded:TRUE);
install = get_single_install(app_name:app, port:port);

version = install['version'];
install_url = build_url2(port:port, qs:install['path']);

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_url);

# only 2.x, 3.x
if (version !~ "^[23]($|\.)")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_url,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
