#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58954);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-3078",
    "CVE-2011-3079",
    "CVE-2011-3080",
    "CVE-2011-3081",
    "CVE-2012-1521"
  );
  script_bugtraq_id(53309);

  script_name(english:"Google Chrome < 18.0.1025.168 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 18.0.1025.168 and is, therefore, affected by the following
vulnerabilities :

  - Use-after-free errors exist related to floating element
    handling and the xml parser. (CVE-2011-3078,
    CVE-2012-1521, CVE-2011-3081)

  - A validation error exists related to Inter-Process
    Communications (IPC). (CVE-2011-3079)

  - A race condition exists in the method
    'CrossCallParamsEx::CreateFromBuffer' in the file
    'sandbox/src/crosscall_server.cc' and is related to
    sandbox Inter-Process Communication (IPC).
    (CVE-2011-3080)");
  # https://chromereleases.googleblog.com/2012/04/stable-channel-update_30.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?578ec32c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 18.0.1025.168 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'18.0.1025.168', severity:SECURITY_HOLE);
