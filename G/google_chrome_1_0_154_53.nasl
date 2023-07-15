#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39449);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-2060", "CVE-2009-2071");
  script_bugtraq_id(35380, 35411);

  script_name(english:"Google Chrome < 1.0.154.53 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.53.  Such versions are reportedly affected by multiple
vulnerabilities :

  - The browser uses the HTTP Host header to determine the
    context of a 4xx/5xx CONNECT response from a proxy
    server. This could allow a man-in-the-middle attacker
    to execute arbitrary script code in the context of a
    legitimate server, circumventing the browser's same-
    origin policy.

  - The browser displays a cached certificate for 4xx/5xx
    CONNECT response pages from a proxy server.  A man-in-
    the-middle attacker could exploit this by displaying a
    spoofed web page with the valid certificate of a
    legitimate website.");
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/research/publication/pretty-bad-proxy-an-overlooked-adversary-in-browsers-https-deployments/?from=http%3A%2F%2Fresearch.microsoft.com%2Fapps%2Fpubs%2Fdefault.aspx%3Fid%3D79323");
  # http://sites.google.com/a/chromium.org/dev/getting-involved/dev-channel/release-notes/releasenotes1015453
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2384355");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 1.0.154.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'1.0.154.53', severity:SECURITY_WARNING);
