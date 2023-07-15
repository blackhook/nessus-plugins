#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77861);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_xref(name:"CERT", value:"772676");

  script_name(english:"Google Chrome < 37.0.2062.124 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by a
signature forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is a version
prior to 37.0.2062.124. It is, therefore, affected by an issue in the
Network Security Services (NSS) libraries. This issue is due to
lenient parsing of ASN.1 values involved in a signature and could lead
to the forgery of RSA signatures, such as SSL certificates.");
  # http://googlechromereleases.blogspot.com/2014/09/stable-channel-update_24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b2e112f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 37.0.2062.124 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1568");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'37.0.2062.124', severity:SECURITY_HOLE, xss:FALSE);
