#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72693);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0050");
  script_bugtraq_id(65400);
  script_xref(name:"EDB-ID", value:"31615");

  script_name(english:"Apache Tomcat 8.0.x < 8.0.3 Content-Type DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 8.0.x listening on the remote host is a version prior to 8.0.3.
It is, therefore, affected by a denial of service vulnerability due to
an error related to handling 'Content-Type' HTTP headers and multipart
requests such as file uploads.

Note that this error exists because of the bundled version of Apache
Commons FileUpload.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.3");
  # http://mail-archives.apache.org/mod_mbox/www-announce/201402.mbox/%3C52F373FC.9030907@apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?358ef049");
  script_set_attribute(attribute:"solution", value:
"Update to Apache Tomcat version 8.0.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0050");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

# Note that 8.0.2 contained the fix,
# but was never released.
tomcat_check_version(fixed:"8.0.2", min:"8.0.0", severity:SECURITY_HOLE, granularity_regex:"^8(\.0)?$");

