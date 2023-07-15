#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35689);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-3670");
  script_bugtraq_id(24837);
  script_xref(name:"SECUNIA", value:"33800");

  script_name(english:"Google Chrome < 1.0.154.48 Cross-browser Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is prone to a cross-
browser scripting attack.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 1.0.154.48.  Such versions are reportedly affected by a protocol-
handler command-injection vulnerability that could allow an attacker to
carry out cross-browser scripting attacks.");
  # https://web.archive.org/web/20090213221425/https://sites.google.com/a/chromium.org/dev/getting-involved/dev-channel/release-notes/release1015448
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?125071e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 1.0.154.48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/16");

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
google_chrome_check_version(installs:installs, fix:'1.0.154.48', severity:SECURITY_WARNING);
