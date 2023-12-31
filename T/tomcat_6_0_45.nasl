#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88935);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-5174",
    "CVE-2015-5345",
    "CVE-2016-0706",
    "CVE-2016-0714"
  );
  script_bugtraq_id(
    83324,
    83327,
    83328,
    83329
  );

  script_name(english:"Apache Tomcat 6.0.x < 6.0.45 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service running on the remote host is 6.0.x prior to 6.0.45. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    getResource(), getResourceAsStream(), and
    getResourcePaths() ServletContext methods due to a
    failure to properly sanitize user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    crafted path traversal request, to gain access to the
    listing of directory contents. (CVE-2015-5174)

  - An information disclosure vulnerability exists due to
    a failure to enforce access restrictions when handling
    directory requests that are missing trailing slashes. An
    unauthenticated, remote attacker can exploit this to
    enumerate valid directories. (CVE-2015-5345)

  - An information disclosure vulnerability exists that
    allows a specially crafted web application to load the
    StatusManagerServlet. An attacker can exploit this to
    gain unauthorized access to a list of all deployed
    applications and a list of the HTTP request lines for
    all requests currently being processed. (CVE-2016-0706)

  - A security bypass vulnerability exists due to a flaw
    in the StandardManager, PersistentManager, and cluster
    implementations that is triggered when handling
    persistent sessions. An unauthenticated, remote attacker
    can exploit this, via a crafted object in a session, to
    bypass the security manager and execute arbitrary code.
    (CVE-2016-0714)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.45
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?713d54e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.45 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");
tomcat_check_version(fixed:"6.0.45", min:"6.0.0", severity:SECURITY_WARNING, granularity_regex:"^6(\.0)?$");

