#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57039);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2011-4010",
    "CVE-2011-4681",
    "CVE-2011-4682",
    "CVE-2011-4683",
    "CVE-2011-4684",
    "CVE-2011-4685",
    "CVE-2011-4686",
    "CVE-2011-4687"
  );
  script_bugtraq_id(
    49778,
    50914,
    50915,
    50916,
    51027,
    55345
  );
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Opera < 11.60 Multiple Vulnerabilities (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is prior to
11.60. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified error exists that can allow URL
    spoofing in the address bar. (CVE-2011-4010)

  - Top level domain separation rules are not honored for
    two-letter top level domains, e.g., '.us' or '.uk', and
    some three-letter top level domains. This error can
    allow sites to set the scripting context to the top
    level domain. Further, this can allow sites to set and 
    read cookies from other sites whose scripting context is 
    set to the same top level domain. (CVE-2011-4681)

  - An error exists in the implementation of the JavaScript
    'in' operator that can allow sites to verify the
    existence of variables of sites in other domains.
    (CVE-2011-4682)

  - An unspecified, moderately severe issue exists. Details
    are to be disclosed by the vendor at a later date.
    (CVE-2011-4683)

  - The browser does not properly handle certain corner
    cases related to certificate revocation. (CVE-2011-4684)

  - Unspecified content can cause the 'Dragonfly' component
    of the browser to crash. (CVE-2011-4685)

  - An unspecified error exists related to the 'Web 
    Workers' implementation that can allow application
    crashes. (CVE-2011-4686)

  - An unspecified error exists that can allow remote
    content to cause denial of service conditions via
    resource consumption. (CVE-2011-4687)

  - An information disclosure vulnerability, known as BEAST,
    exists in the SSL 3.0 and TLS 1.0 protocols due to a
    flaw in the way the initialization vector (IV) is
    selected when operating in cipher-block chaining (CBC)
    modes. A man-in-the-middle attacker can exploit this
    to obtain plaintext HTTP header data, by using a
    blockwise chosen-boundary attack (BCBA) on an HTTPS
    session, in conjunction with JavaScript code that uses
    the HTML5 WebSocket API, the Java URLConnection API,
    or the Silverlight WebClient API. (CVE-2011-3389)");
  script_set_attribute(attribute:"see_also", value:"http://netifera.com/research/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1003/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1004/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1005/");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20170912020716/http://www.opera.com:80/docs/changelogs/windows/1160/");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 11.60 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");
version_ui = get_kb_item("SMB/Opera/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui; 

fixed_version = "11.60.1185.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "11.60")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else
  fixed_version_report = "11.60";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    install_path = get_kb_item("SMB/Opera/Path");

    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
