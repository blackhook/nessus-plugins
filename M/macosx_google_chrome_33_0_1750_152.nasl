#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73083);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id(
    "CVE-2014-1705",
    "CVE-2014-1713",
    "CVE-2014-1714",
    "CVE-2014-1715"
  );
  script_bugtraq_id(
    66239,
    66243,
    66249,
    66252
  );

  script_name(english:"Google Chrome < 33.0.1750.152 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Mac OS X host is
a version prior to 33.0.1750.152. It is, therefore, affected by the
following vulnerabilities :

  - A remote code-execution flaw exists due to a read/write
    error with the a sandbox bypass, specifically the V8
    JavaScript engine. This could allow an attacker to
    execute code or cause a denial of service if the exploit
    fails. (CVE-2014-1705)

  - A use-after-free flaw exists with the
    'document.location' bindings. An attacker, using a
    specially crafted web page, can dereference freed memory
    and could execute arbitrary code. (CVE-2014-1713)

  - A flaw exists with the clipboard message filter. A
    context-dependent attacker could bypass sandbox
    restrictions. (CVE-2014-1714)

  - A restriction bypass flaw exists with the
    'CreatePlatformFileUnsafe()' function in the
    'base/platform_file_win.cc' where user input is not
    properly sanitized. A context-dependent attacker could
    open arbitrary directories bypassing sandbox
    restrictions. (CVE-2014-1715)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531614/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531615/30/0/threaded");
  # http://googlechromereleases.blogspot.com/2014/03/stable-channel-update_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?caf96baa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 33.0.1750.152 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'33.0.1750.152', severity:SECURITY_HOLE);
