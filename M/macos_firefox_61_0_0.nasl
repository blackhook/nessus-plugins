#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110806);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-5156",
    "CVE-2018-5186",
    "CVE-2018-5187",
    "CVE-2018-5188",
    "CVE-2018-12358",
    "CVE-2018-12359",
    "CVE-2018-12360",
    "CVE-2018-12361",
    "CVE-2018-12362",
    "CVE-2018-12363",
    "CVE-2018-12364",
    "CVE-2018-12365",
    "CVE-2018-12366",
    "CVE-2018-12367",
    "CVE-2018-12368",
    "CVE-2018-12369",
    "CVE-2018-12370",
    "CVE-2018-12371"
  );
  script_bugtraq_id(
    104246,
    104555,
    104556,
    104557,
    104558,
    104560,
    104561,
    104562
  );
  script_xref(name:"MFSA", value:"2018-15");

  script_name(english:"Mozilla Firefox < 61 Multiple Critical Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
    affected by multiple critical and high severity vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or
    Mac OS X host is prior to 61. It is, therefore, affected by multiple
    critical and high severity vulnerabilities.");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf08db1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 61.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'61.0.0', severity:SECURITY_HOLE);
