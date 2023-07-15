##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141566);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2012-1007",
    "CVE-2014-0114",
    "CVE-2016-1181",
    "CVE-2016-1182"
  );

  script_name(english:"IBM WebSphere Application Server 7.0.0.x <= 7.0.0.45 / 8.0.0.x <= 8.0.0.15 / 8.5.x < 8.5.5.14 / 9.0.x <= 9.0.0.9 Multiple Vulnerabilities (711865)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 7.0.0.x through 7.0.0.45, 8.0.0.x through
8.0.0.15, 8.5.0.x prior to 8.5.5.14 or 9.0.x prior to 9.0.0.9. It is, therefore, affected by multiple vulnerabilities
related to Apache Struts, including the following:

  - Apache Commons BeanUtils, as distributed in lib/commons-beanutils-1.8.0.jar in Apache Struts 1.x through
    1.3.10 and in other products requiring commons-beanutils through 1.9.2, does not suppress the class
    property, which allows remote attackers to manipulate the ClassLoader and execute arbitrary code via the
    class parameter, as demonstrated by the passing of this parameter to the getClass method of the ActionForm
    object in Struts 1. (CVE-2014-0114)

  - ActionServlet.java in Apache Struts 1 1.x through 1.3.10 mishandles multithreaded access to an ActionForm
    instance, which allows remote attackers to execute arbitrary code or cause a denial of service (unexpected
    memory access) via a multipart request, a related issue to CVE-2015-0899. (CVE-2016-1181)

  - ActionServlet.java in Apache Struts 1 1.x through 1.3.10 does not properly restrict the Validator
    configuration, which allows remote attackers to conduct cross-site scripting (XSS) attacks or cause a
    denial of service via crafted input, a related issue to CVE-2015-0899. (CVE-2016-1182)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/711865");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.14, 9.0.0.9, or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PI97162.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0114");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-1182");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Only vulnerable when using the optiona UDDI.ear
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PI97162';

app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PI97162' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.45', 'fixed_version':fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.15', 'fixed_version':fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.13', 'fixed_version':'8.5.5.14 or ' + fix},
  {'min_version':'9.0.0.0', 'max_version':'9.0.0.8', 'fixed_version':'9.0.0.9 or ' + fix}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
