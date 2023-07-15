#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47576);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-5333",
    "CVE-2007-5342",
    "CVE-2007-5461",
    "CVE-2007-6286"
  );
  script_bugtraq_id(
    26070,
    27006,
    27706,
    49470
  );
  script_xref(name:"SECUNIA", value:"27398");
  script_xref(name:"SECUNIA", value:"28274");
  script_xref(name:"SECUNIA", value:"28878");

  script_name(english:"Apache Tomcat < 5.5.26 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat listening on the remote host is prior to 5.5.26. It is,
therefore, affected by multiple vulnerabilities :

  - The remote Apache Tomcat install may be vulnerable to an
    information disclosure attack via cookies. The previous
    fix for CVE-2007-3385 was incomplete and did not account
    for the use of quotes or '%5C' in cookie values.
    (CVE-2007-3385, CVE-2007-5333)

  - The default security policy in the JULI logging
    component did not restrict access permissions to files.
    This could be misused by untrusted web applications to
    access and write arbitrary files in the context of the
    tomcat process. (CVE-2007-5342)

  - The remote Apache Tomcat install may be vulnerable to an
    information disclosure attack via the WebDAV servlet.
    Certain WebDAV requests, containing an entity with a
    SYSTEM tag can result in the disclosure of arbitrary
    file contents. (CVE-2007-5461)

  - When the native APR connector is used, it does not
    properly handle an empty request to the SSL port, which
    allows remote attackers to trigger handling of a
    duplicate copy of one of the recent requests, as
    demonstrated by using netcat to send the empty request.
    (CVE-2007-6286)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 5.5.26 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-5333");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 200, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"5.5.26", min:"5.5.0", severity:SECURITY_WARNING, granularity_regex:"^5(\.5)?$");

