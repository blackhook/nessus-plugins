##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(173301);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2023-0568", "CVE-2023-0662", "CVE-2023-25690");
  script_xref(name:"IAVA", value:"2023-A-0124");
  script_xref(name:"IAVA", value:"2023-A-0105-S");

  script_name(english:"Tenable SecurityCenter < 6.1.0 Multiple Vulnerabilities (TNS-2023-16)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
running 6.0.0 or earlier and is therefore affected by multiple vulnerabilities in Apache prior to version 2.4.56
and PHP prior to version 8.1.16:

    - Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request 
      Smuggling attack. Configurations are affected when mod_proxy is enabled along with some form of RewriteRule
      or ProxyPassMatch in which a non-specific pattern matches some portion of the user-supplied request-target 
      data and is then re-inserted into the proxied request-target using variable substitution. (CVE-2023-25690)

    - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, excessive number of parts in HTTP 
      form upload can cause high resource consumption and excessive number of log entries. This can cause denial 
      of service on the affected server by exhausting CPU resources or disk space. (CVE-2023-0662)

    - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, core path resolution function 
      allocate buffer one byte too small. When resolving paths with lengths close to system MAXPATHLEN setting, 
      this may lead to the byte after the allocated buffer being overwritten with NUL value, which might lead to 
      unauthorized data access or modification. (CVE-2023-0568)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-16");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2023.htm#Tenable.sc-6.1.0-(2023-03-22)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c45a331");
  script_set_attribute(attribute:"solution", value:
"Update to Tenable SecurityCenter 6.1.0 or later or apply the security patches referenced in the advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25690");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

# Advisory associated with multiple CVEs, remediated either by installing two patches or upgrading to 6.1.x
if (('SC-202303.2' >!< app_info['installed_patches']) && ('SC-202304.1' >< app_info['installed_patches']))
{
  var constraints = [
    { 'min_version' : '5.18.0', 'max_version': '6.0.0', 'fixed_display' : 'Upgrade to 6.1.0 or later, or apply patch SC-202303.2'}
  ];
}

if (('SC-202304.1' >!< app_info['installed_patches']) && ('SC-202303.2' >< app_info['installed_patches']))
{
  constraints = [
    { 'min_version' : '5.18.0', 'max_version': '6.0.0', 'fixed_display' : 'Upgrade to 6.1.0 or later, or apply patch SC-202304.1'}
  ];
}

if (('SC-202304.1' >!< app_info['installed_patches']) && ('SC-202303.2' >!< app_info['installed_patches']))
{
  constraints = [
    { 'min_version' : '5.18.0', 'max_version': '6.0.0', 'fixed_display' : 'Upgrade to 6.1.0 or later, or apply patches SC-202303.2 and SC-202304.1'}
  ];
}

if (('SC-202304.1' >< app_info['installed_patches']) && ('SC-202303.2' >< app_info['installed_patches']))
  ::audit(AUDIT_HOST_NOT, "affected");
  
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
