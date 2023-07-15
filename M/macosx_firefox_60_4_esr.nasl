#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119605);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-12405",
    "CVE-2018-17466",
    "CVE-2018-18492",
    "CVE-2018-18493",
    "CVE-2018-18494",
    "CVE-2018-18498"
  );

  script_name(english:"Mozilla Firefox ESR < 60.4 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox ESR.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote macOS host
is prior to 60.4. It is, therefore, affected by multiple
vulnerabilities as noted in Mozilla Firefox ESR stable channel update
release notes for 2018/12/11. Please refer to the release notes for
additional information. Note that Nessus has not attempted to exploit
these issues but has instead relied only on the application's self-
reported version number.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487964
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfb534bf");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1488295
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?073e58a5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1494752
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d00e047");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498765
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4de96e6");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1499861
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20902119");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1500011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cee5fb79");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1500759
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b6def6c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1502013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c1b25bb");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1503082
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74015e4e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1503326
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56acb454");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1504365
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d52ad8b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1504452
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c09a06dc");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1505181
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d477b15c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1506640
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59cea44c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1510471
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e37f4f1");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-30/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab18b5fb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 60.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'60.4', min:'60.0', severity:SECURITY_HOLE);
