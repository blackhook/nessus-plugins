#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42798);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-2816");
  script_bugtraq_id(36997);
  script_xref(name:"SECUNIA", value:"37358");

  script_name(english:"Google Chrome < 3.0.195.33 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 3.0.195.33.  Such versions are reportedly affected by a security
bypass vulnerability caused by cusom headers being incorrectly sent for
'CORS OPTIONS' requests.  A malicious website operator could set custom
HTTP headers on cross-origin 'OPTIONS' requests.");
  # https://chromereleases.googleblog.com/2009/11/stable-update-fix-google-chrome-not.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b1c01d6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 3.0.195.33 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/13");

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
google_chrome_check_version(installs:installs, fix:'3.0.195.33', severity:SECURITY_WARNING);
