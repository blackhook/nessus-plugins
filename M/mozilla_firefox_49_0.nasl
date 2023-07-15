#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117941);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2016-2827",
    "CVE-2016-5256",
    "CVE-2016-5257",
    "CVE-2016-5270",
    "CVE-2016-5271",
    "CVE-2016-5272",
    "CVE-2016-5273",
    "CVE-2016-5274",
    "CVE-2016-5275",
    "CVE-2016-5276",
    "CVE-2016-5277",
    "CVE-2016-5278",
    "CVE-2016-5279",
    "CVE-2016-5280",
    "CVE-2016-5281",
    "CVE-2016-5282",
    "CVE-2016-5283",
    "CVE-2016-5284"
  );

  script_name(english:"Mozilla Firefox < 49 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 49. It is, therefore, affected by multiple vulnerabilities as
noted in Mozilla Firefox stable channel update release notes for
2016/09/20. Please refer to the release notes for additional
information. Note that Nessus has not attempted to exploit these
issues but has instead relied only on the application's self-reported
version number.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1249522
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a71b5c71");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1268034
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27887241");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1276413
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4caa1ed8");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1277213
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32eb4c7a");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1280387
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ef629bf");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1282076
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8865b1d7");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1282746
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?160280d4");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1284690
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5dbbf44e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1287204
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54ac5d09");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1287316
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3bfda65");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1287721
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d89bb27");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1288555
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f45fb2ce");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1288588
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47a40c69");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1288780
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0baaaa08");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1288946
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1181d174");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1289085
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2269f975");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1289280
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b74c22ad");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1289970
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7882d62d");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1290244
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e281edf");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1291016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?117622e5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1291665
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b353376");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1293347
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6207b3c0");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1294095
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e04baf7");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1294407
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?527385b7");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1294677
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40b8f022");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1296078
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d9488e8");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1296087
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c74b0ed3");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1297099
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e935ffb");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=129793
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5be7ccc");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1303127
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c34feae8");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=928187
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c773d903");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=932335
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e86e0c1");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2016-85/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b727e4e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 49 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'49', severity:SECURITY_HOLE);
