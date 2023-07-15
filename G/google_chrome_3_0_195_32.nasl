#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42413);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-3931", "CVE-2009-3932");
  script_bugtraq_id(36947);
  script_xref(name:"SECUNIA", value:"37273");

  script_name(english:"Google Chrome < 3.0.195.32 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 3.0.195.32.  Such versions are reportedly affected by multiple
issues :

  - The user is not warned about certain dangerous file
    types such as 'SVG', 'MHT', and 'XML'. In some browsers,
    JavaScript can execute within these types of files.
    (Issue #23979)

  - A malicious site could use the Gears SQL API to put SQL
    metadata into a bad state, which could cause a
    subsequent memory corruption which could lead the Gears
    plugin to crash, or possibly allow arbitrary code
    execution. (Issue #26179)");
  # https://chromereleases.googleblog.com/2009/11/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?525a1e42");
  # http://securethoughts.com/2009/11/using-blended-browser-threats-involving-chrome-to-steal-files-on-your-computer/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5c8ae4f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 3.0.195.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/06");

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
google_chrome_check_version(installs:installs, fix:'3.0.195.32', severity:SECURITY_HOLE);
