#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
# Disabled on 14/10/2021, due to wrong plugin generation
#
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153924);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2014-3577",
    "CVE-2021-21682",
    "CVE-2021-21683",
    "CVE-2021-21684"
  );
  script_xref(name:"IAVA", value:"2021-A-0460-S");

  script_name(english:"Jenkins Git Plugin < 4.8.3 / Jenkins LTS < 2.303.2 / Jenkins weekly < 2.315 Multiple Vulnerabilities (Deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. Please use plugin 153924 instead.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2021-10-06");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl");
  script_require_keys("www/Jenkins");
  script_require_ports("Services/www", 8080);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use jenkins_2_315.nasl (plugin ID 153924) instead.");