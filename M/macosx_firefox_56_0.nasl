#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103678);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-7793",
    "CVE-2017-7805",
    "CVE-2017-7810",
    "CVE-2017-7811",
    "CVE-2017-7812",
    "CVE-2017-7813",
    "CVE-2017-7814",
    "CVE-2017-7815",
    "CVE-2017-7816",
    "CVE-2017-7817",
    "CVE-2017-7818",
    "CVE-2017-7819",
    "CVE-2017-7820",
    "CVE-2017-7821",
    "CVE-2017-7822",
    "CVE-2017-7823",
    "CVE-2017-7824",
    "CVE-2017-7825"
  );
  script_bugtraq_id(
    101053,
    101054,
    101055,
    101057,
    101059
  );
  script_xref(name:"MFSA", value:"2017-21");

  script_name(english:"Mozilla Firefox < 56 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or Mac
OS X host is prior to 56. It is, therefore, affected by multiple
vulnerabilities, some of which allow code execution and potentially
exploitable application crashes.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-21/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 56 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7811");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'56', severity:SECURITY_HOLE);
