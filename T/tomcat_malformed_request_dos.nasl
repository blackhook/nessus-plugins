#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17322);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-0808");
  script_bugtraq_id(12795);

  script_name(english:"Apache Tomcat AJP12 Protocol Malformed Packet Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote AJP connector is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Apache Tomcat running on the remote host is affected by a
denial of service vulnerability due to a failure to handle malformed input. By submitting a specially crafted AJP12
request, an unauthenticated attacker can cause Tomcat to stop responding. At present, details on the specific nature of
such requests are not generally known.");
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/JGEI-6A2LEF");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 5.x or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"5.0.0", severity:SECURITY_WARNING);
