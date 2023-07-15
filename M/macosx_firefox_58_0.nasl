#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106301);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2018-5089",
    "CVE-2018-5090",
    "CVE-2018-5091",
    "CVE-2018-5092",
    "CVE-2018-5093",
    "CVE-2018-5094",
    "CVE-2018-5095",
    "CVE-2018-5097",
    "CVE-2018-5098",
    "CVE-2018-5099",
    "CVE-2018-5100",
    "CVE-2018-5101",
    "CVE-2018-5102",
    "CVE-2018-5103",
    "CVE-2018-5104",
    "CVE-2018-5105",
    "CVE-2018-5106",
    "CVE-2018-5107",
    "CVE-2018-5108",
    "CVE-2018-5109",
    "CVE-2018-5110",
    "CVE-2018-5111",
    "CVE-2018-5112",
    "CVE-2018-5113",
    "CVE-2018-5114",
    "CVE-2018-5115",
    "CVE-2018-5116",
    "CVE-2018-5117",
    "CVE-2018-5118",
    "CVE-2018-5119",
    "CVE-2018-5121",
    "CVE-2018-5122"
  );
  script_bugtraq_id(102783);
  script_xref(name:"MFSA", value:"2018-02");

  script_name(english:"Mozilla Firefox < 58 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or Mac
OS X host is prior to 58. It is, therefore, affected by multiple
vulnerabilities, some of which allow code execution and potentially
exploitable crashes.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-02/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 58 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5090");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'58', severity:SECURITY_HOLE);
