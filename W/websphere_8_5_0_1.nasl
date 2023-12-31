#
# (C) Tenable Network Security, Inc.
#




include("compat.inc");

if (description)
{
  script_id(62975);
  script_version("1.12");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2012-2159",
    "CVE-2012-2190",
    "CVE-2012-2191",
    "CVE-2012-3293",
    "CVE-2012-3304",
    "CVE-2012-3305",
    "CVE-2012-3306",
    "CVE-2012-3311",
    "CVE-2012-3325",
    "CVE-2012-3330",
    "CVE-2012-4850",
    "CVE-2012-4851",
    "CVE-2012-4853"
  );
  script_bugtraq_id(
    53884,
    54743,
    55149,
    55185,
    55309,
    55671,
    55678,
    56423,
    56458,
    56459,
    56460
  );

  script_name(english:"IBM WebSphere Application Server 8.5 < Fix Pack 1 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server may be affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 8.5 before Fix Pack 1 appears to be
running on the remote host and is, therefore, potentially affected by
the following vulnerabilities :

  - An input validation error exists related to the 'Eclipse
    Help System' that can allow arbitrary redirect responses
    to HTTP requests. (CVE-2012-2159, PM66410)

  - Several errors exist related to SSL/TLS that can allow
    an attacker to carry out denial of service attacks
    against the application. (CVE-2012-2190, CVE-2012-2191,
    PM66218)
 
  - Unspecified cross-site scripting issues exist related to
    the administrative console. (CVE-2012-3293, PM60839)

  - An unspecified error in the 'ISC Console' can allow a
    remote attacker to take over a valid user's session.
    (CVE-2012-3304, PM54356)

  - An unspecified directory traversal error exists that
    can allow remote attackers to overwrite files outside
    the application's deployment directory. (CVE-2012-3305,
    PM62467)

  - When multi-domain support is enabled, the application
    does not properly purge passwords from the
    authentication cache. (CVE-2012-3306, PM66514)

  - An error exists related to 'Federated Repositories',
    'IIOP' connections, 'CBIND' checking and 'Optimized
    Local Adapters' that can allow a remote attacker to
    bypass security restrictions. Note that this issue
    affects the application when running on z/OS.
    (CVE-2012-3311, PM61388)

  - The fix contained in PM44303 contains an error that
    can allow an authenticated attacker to bypass security
    restrictions and gain administrative access to the
    application. (CVE-2012-3325, PM71296) 

  - A request validation error exists related to the proxy
    server component that can allow a remote attacker to
    cause the proxy status to be reported as disabled thus
    denying applications access to the proxy.
    (CVE-2012-3330, PM71319)

  - A request validation error exists related to the
    'Liberty Profile' and 'JAX-RS' that can allow a remote
    attacker to elevate privileges. (CVE-2012-4850, PM67082)

  - A user-supplied input validation error exists related
    to the 'Liberty Profile' that can allow cross-site
    scripting attacks to be carried out. (CVE-2012-4851,
    PM68643)

  - A user-supplied input validation error exists that can
    allow cross-site request forgery (CSRF) attacks to be
    carried out. (CVE-2012-4853, PM62920)");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/potential_security_exposure_from_ibm_websphere_application_server_impacts_rational_application_developer_cve_2012_33256?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bad06dcb");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_directory_server_potential_security_exposure_with_ibm_websphere_application_server_apar_pm44303_cve_2012_33253?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58770565");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_federated_identity_manager_potential_security_exposure_with_ibm_websphere_application_server_apar_pm44303_cve_2012_33252?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80adf3bd");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_access_manager_for_e_business_potential_security_exposure_with_ibm_websphere_application_server_apar_pm44303_cve_2012_33253?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcf28d02");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21618044");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21620517");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21620518");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033606");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?&uid=swg21614265");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27036319#8501");
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 1 for version 8.5 (8.5.0.1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl");
  script_require_keys("www/WebSphere");
  script_require_ports("Services/www", 8880, 8881);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:0);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

if (version !~ "^8\.5([^0-9]|$)") exit(0, "The version of the IBM WebSphere Application Server instance listening on port "+port+" is "+version+", not 8.5.");

if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 5 && ver[2] == 0 && ver[3] < 1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.5.0.1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
