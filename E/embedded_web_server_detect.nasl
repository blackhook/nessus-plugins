#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19689);
 script_version("1.83");
 script_cvs_date("Date: 2019/11/22");

 script_name(english:"Embedded Web Server Detection");
 script_summary(english:"This scripts detects whether the remote host is an embedded web server.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is embedded.");
 script_set_attribute(attribute:"description", value:
"The remote web server cannot host user-supplied CGIs. CGI scanning
will be disabled on this server.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cesanta:mongoose_embedded_web_server_library");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_family(english:"Web Servers");

 script_dependencies("cisco_ids_manager_detect.nasl", "ciscoworks_detect.nasl", "ilo_detect.nasl",
"clearswift_mimesweeper_smtp_detect.nasl", "imss_detect.nasl", "interspect_detect.nasl", "intrushield_console_detect.nasl", "ibm_rsa_www.nasl",
"veritas_cluster_mgmt_detect.nasl",	# Not an embedded web server per se
"iwss_detect.nasl", "linuxconf_detect.nasl", "securenet_provider_detect.nasl",
"tmcm_detect.nasl", "websense_detect.nasl", "xedus_detect.nasl", "xerox_document_centre_detect.nasl", "xerox_workcentre_detect.nasl", "compaq_wbem_detect.nasl", "drac_detect.nasl", "net_optics_director_web_detect.nbin");

 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_service(svc:"www", default:80, exit_on_fail:TRUE);
embedded_flag = get_kb_item("Services/www/"+port+"/embedded");
if (empty_or_null(embedded_flag) || embedded_flag == FALSE)
{
	banner = get_http_banner(port:port);
	if (empty_or_null(banner))
	{
		audit(AUDIT_WEB_BANNER_NOT, port);
	}

	if (!(port == 901 || is_embedded_server(banner)))
	{
		audit(AUDIT_WRONG_WEB_SERVER, port, "known to be embedded");
	}

	replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
}

security_report_v4(severity:SECURITY_NOTE, port:port);
