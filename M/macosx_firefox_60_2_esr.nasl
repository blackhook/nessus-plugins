#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117292);
  script_version("1.7");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id(
    "CVE-2017-16541",
    "CVE-2018-12376",
    "CVE-2018-12377",
    "CVE-2018-12378",
    "CVE-2018-12379",
    "CVE-2018-12381",
    "CVE-2018-18499"
  );
  script_bugtraq_id("101665");
  script_xref(name:"MFSA", value:"2018-21");

  script_name(english:"Mozilla Firefox ESR < 60.2 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox ESR.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote macOS or
Mac OS X host is prior to 60.2. It is, therefore, affected by
multiple vulnerabilities, some of which allow code execution and
potentially exploitable crashes.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1412081
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eeb4654f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1435319
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f8c53b5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1450989
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20fb56d5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1459383
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ba771ab");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1466577
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec8a52cc");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1466991
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?729f9359");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1467363
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1de4cab5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1467889
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5d40321");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1468523
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38d5db79");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1468738
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e15e66a");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1469309
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71d5c763");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1469914
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0410b02e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1470260
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c939fbe7");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1471953
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06cc0e92");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1472925
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?635f0fa0");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1473113
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4376815f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1473161
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99b48daf");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1478575
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdfa1d66");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1478849
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0c0acea");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1480092
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69cce0e2");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1480517
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae70d802");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1480521
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd5f0586");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1481093
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d6a368a");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483120
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61040df6");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-21/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?387cd93f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 62.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12376");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/06");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'60.2', min:'60.0', severity:SECURITY_HOLE);
