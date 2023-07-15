#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177741);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-32315");
  script_xref(name:"IAVB", value:"2023-B-0043");

  script_name(english:"Openfire 3.10 < 4.6.8 / 4.7 < 4.7.5 Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Openfire that is affected by an authentication bypass vulnerability. Openfire
is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based
application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an
unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire
environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This
vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0.
The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the
yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to
upgrade. If an Openfire upgrade isn’t available for a specific release, or isn’t quickly actionable, users may see the
linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dec8dfe3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.6.8, 4.7.5, 4.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32315");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igniterealtime:openfire");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 Tenable Network Security, Inc.");

  script_dependencies("openfire_console_detect.nasl");
  script_require_keys("installed_sw/Openfire Console");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Openfire Console');

var constraints = [
  {'min_version' : '3.10', 'fixed_version' : '4.6.8'},
  {'min_version' : '4.7', 'fixed_version' : '4.7.5', 'fixed_display' : '4.7.5 / 4.8.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
