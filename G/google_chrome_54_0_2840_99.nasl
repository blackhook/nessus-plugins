#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94676);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-5199",
    "CVE-2016-5200",
    "CVE-2016-5201",
    "CVE-2016-5202"
  );
  script_bugtraq_id(94196);

  script_name(english:"Google Chrome < 54.0.2840.99 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 54.0.2840.99. It is, therefore, affected by the following
vulnerabilities :

  - A remote code execution vulnerability exists in the
    FFmpeg component due to an integer overflow condition in
    the mov_read_keys() function in mov.c caused by improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a website containing specially crafted content,
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2016-5199)

  - A denial of service vulnerability exists in the V8
    component due to an out-of-bounds read error that is
    triggered when handling 'Math.sign'. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a website containing specially crafted content,
    to crash the browser or disclose memory contents.
    (CVE-2016-5200)

  - An information disclosure vulnerability exists due to a
    flaw in the expose() function in utils.js. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a website containing
    specially crafted content, to disclose sensitive
    internal class information. (CVE-2016-5201)

  - An unspecified vulnerability exists in the
    PruneExpiredDevices() function in dial_registry.cc that
    allows an unauthenticated, remote attacker to have an
    unspecified impact. (CVE-2016-5202)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://googlechromereleases.blogspot.com/2016/11/stable-channel-update-for-desktop_9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdb7f5cb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 54.0.2840.99 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5202");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'54.0.2840.99', severity:SECURITY_HOLE);
