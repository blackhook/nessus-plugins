#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2019/05/08. Deprecated by macos_firefox_64_0.nasl

include("compat.inc");

if (description)
{
  script_id(119603);
  script_version("1.4");
  script_cvs_date("Date: 2019/05/08 12:46:36");

  script_cve_id(
    "CVE-2018-12405",
    "CVE-2018-12406",
    "CVE-2018-12407",
    "CVE-2018-17466",
    "CVE-2018-18492",
    "CVE-2018-18493",
    "CVE-2018-18494",
    "CVE-2018-18495",
    "CVE-2018-18496",
    "CVE-2018-18497",
    "CVE-2018-18498"
  );

  script_name(english:"Mozilla Firefox < 64.0 Multiple Vulnerabilities (macOS) (deprecated)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin is a duplicate of plugin ID 122192 and has been
deprecated.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1422231
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39cf90b2");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1427585
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49133ad0");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1434490
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e2ade34");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1456947
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0ce18e5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1458129
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea477541");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1475669
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1620e461");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1481745
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b42f7123");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487964
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfb534bf");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1488180
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c97806f0");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1488295
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?073e58a5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1494752
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d00e047");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498765
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4de96e6");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1499198
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82d76ead");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1499861
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20902119");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1500011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cee5fb79");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1500064
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2d4d47b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1500310
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4a48a6c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1500696
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dfc8a45");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1500759
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b6def6c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1502013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c1b25bb");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1502886
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?393f22fe");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1503082
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74015e4e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1503326
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56acb454");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1504365
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d52ad8b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1504452
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c09a06dc");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1504816
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b722444");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1505181
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d477b15c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1505973
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a4b622a");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1506640
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59cea44c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1510471
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e37f4f1");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-29/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43f8626d");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12405");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/12");

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

# DEPRECATED 08 MAY 2019 / use plugin ID
exit(0, "This plugin has been deprecated. Use macos_firefox_64_0.nasl (plugin ID 122192) instead.");

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'64.0', severity:SECURITY_HOLE);
