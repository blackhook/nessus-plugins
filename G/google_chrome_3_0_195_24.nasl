#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(41958);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-0689");
  script_bugtraq_id(36565);
  script_xref(name:"SECUNIA", value:"36913");

  script_name(english:"Google Chrome < 3.0.195.24 dtoa Implementation Remote Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 3.0.195.24.  A boundary error in the dtoa() function can lead to a
buffer overflow.  A remote attacker could exploit this by tricking a
user into visiting a malicious web page, which could result in arbitrary
code execution within the Google Chrome sandbox.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 3.0.195.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/01");

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
google_chrome_check_version(installs:installs, fix:'3.0.195.24', severity:SECURITY_WARNING);
