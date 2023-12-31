#
# (C) Tenable Network Security, Inc.
#




include("compat.inc");

if (description)
{
  script_id(59728);
  script_version("1.13");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id(
    "CVE-2011-1377",
    "CVE-2012-0193",
    "CVE-2012-0716",
    "CVE-2012-0717",
    "CVE-2012-0720",
    "CVE-2012-2170"
  );
  script_bugtraq_id(
    50310,
    51441,
    52721,
    52722,
    52724,
    53755
  );

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 23 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 23 appears to be
running on the remote host.  As such, it is potentially affected by
the following vulnerabilities :

  - A security exposure when using WS-Security could result
    in a user gaining elevated privileges in applications
    using JAX-RPC. (PM45181 / CVE-2011-1377)

  - SSL client certificate authentication can be bypassed
    when all of the following are true (PM52351) :

      - SSL is enabled with 'SSLEnable'
      - SSL client authentication is enabled with
        'SSLClientAuth required_reset'. This is not enabled
        by default. Also note, 'SSLClientAuth required' is
        not affected.
      - SSLv2 has not been disabled with
        'SSLProtocolDisable SSLv2'
      - 'SSLClientAuthRequire' is not enabled

  - Unspecified cross-site scripting issues exist related to
    the administrative console. (PM52274, PM53132)

  - An error exists related to 'Application Snoop Servlet'
    and missing access controls. This error can allow
    sensitive information to be disclosed. (PM56183)

  - An issue related to the weak randomization of Java hash
    data structures can allow a remote attacker to cause a
    denial of service with maliciously crafted POST requests.
    (PM53930)");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/potential_security_vulnerability_when_using_web_based_applications_on_ibm_websphere_application_server_due_to_java_hashtable_implementation_vulnerability_cve_2012_0193?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca3789f7");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21587536");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21577532");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24032493");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463#70023");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 23 (7.0.0.23) or
later.

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

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


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:0);


version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 23)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.23' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
