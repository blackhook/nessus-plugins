#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117291);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id(
    "CVE-2017-16541",
    "CVE-2018-12375",
    "CVE-2018-12376",
    "CVE-2018-12377",
    "CVE-2018-12378",
    "CVE-2018-12379",
    "CVE-2018-12381",
    "CVE-2018-12382",
    "CVE-2018-12383"
  );
  script_bugtraq_id(101665);
  script_xref(name:"MFSA", value:"2018-20");

  script_name(english:"Mozilla Firefox < 62 Multiple Critical Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
    "A web browser installed on the remote macOS or Mac OS X host is
    affected by multiple critical and high severity vulnerabilities.");
  script_set_attribute(attribute:"description", value:
    "The version of Mozilla Firefox installed on the remote macOS or
    Mac OS X host is prior to 62. It is, therefore, affected by multiple
    critical and high severity vulnerabilities.");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-20/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8517426b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 62.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12377");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'62.0.0', severity:SECURITY_HOLE);
