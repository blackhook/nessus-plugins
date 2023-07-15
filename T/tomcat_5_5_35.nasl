#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57540);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-4858", "CVE-2012-0022");
  script_bugtraq_id(51200, 51447);
  script_xref(name:"CERT", value:"903934");

  script_name(english:"Apache Tomcat 5.x < 5.5.35 Hash Collision Denial of Service");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 5.x listening on the remote host is prior to 5.5.35. It is,
therefore, affected by a denial of service vulnerability.

Large numbers of crafted form parameters can cause excessive CPU
consumption due to hash collisions.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://mail-archives.apache.org/mod_mbox/tomcat-announce/201112.mbox/%3C4EFB9800.5010106%40apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d97dc97c");
  script_set_attribute(attribute:"see_also", value:"http://www.nruns.com/_downloads/advisory28122011.pdf");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.35");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tomcat 5.5.35 or later. Alternatively, as a workaround, set
the 'maxPostSize' configuration variable to the lowest sensible value
required to support your hosted applications.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4858");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"5.5.35", min:"5.0.0", severity:SECURITY_WARNING, granularity_regex:"^5(\.5)?$");

