#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81579);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0227");
  script_bugtraq_id(72717);

  script_name(english:"Apache Tomcat 6.0.x < 6.0.42 Handling Request Smuggling DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
server running on the remote host is 6.0.x prior to version 6.0.42. It
is, therefore, affected by a flaw in 'ChunkedInputFilter.java' due to
improper handling of attempts to continue reading data after an error
has occurred. A remote attacker, using streaming data with malformed
chunked transfer coding, can exploit this to conduct HTTP request
smuggling or cause a denial of service.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2015/Feb/65");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/tomcat-6.0-doc/changelog.html");
  script_set_attribute(attribute:"solution", value:
"Update to Apache Tomcat version 6.0.43 or later.

Note that while version 6.0.42 fixes the issue, it was not officially
released, and the vendor recommends upgrading to 6.0.43 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

# Note that 6.0.42 contained the fix,
# but was never released
tomcat_check_version(fixed:"6.0.42", min:"6.0.0", severity:SECURITY_WARNING, granularity_regex:"^6(\.0)?$");

