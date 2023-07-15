#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74249);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0119");
  script_bugtraq_id(67669);

  script_name(english:"Apache Tomcat 8.0.x < 8.0.6 XML Parser Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 8.0.x listening on the remote host is a version prior to 8.0.5.
It is, therefore, affected by an information disclosure vulnerability.
An error exists that allows undesired XML parsers to be injected into
the application by a malicious web application, the bypassing security
controls, and the processing of external XML entities.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.0.8 or later.

Note that while version 8.0.6 fixes these issues, that version as well
as 8.0.7 were not officially released, and the vendor recommends
upgrading to 8.0.8 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/30");

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

# Note that 8.0.6 and 8.0.7
# are not affected, but were not released
tomcat_check_version(fixed:"8.0.6", min:"8.0.0", severity:SECURITY_WARNING, granularity_regex:"^8(\.0)?$");

