#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118592);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/06");

  script_cve_id(
    "CVE-2018-12389",
    "CVE-2018-12390",
    "CVE-2018-12391",
    "CVE-2018-12392",
    "CVE-2018-12393"
  );

  script_name(english:"Mozilla Thunderbird < 60.3 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Thunderbird installed on the remote macOS host
is prior to 60.3. It is, therefore, affected by multiple
vulnerabilities as noted in Mozilla Thunderbird stable channel update
release notes for 2018/10/31. Please refer to the release notes for
additional information. Note that Nessus has not attempted to exploit
these issues but has instead relied only on the application's self-
reported version number.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1442010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?614520ad");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1443748
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99f950cc");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1469486
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec6f6183");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1478843
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a30fef4e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1481844
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a288c2");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483699
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56a8a5aa");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1483905
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10a58f5f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1484905
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56bedc2c");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fa35353");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1487660
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6af37c5b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1488803
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55d351a5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1490234
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82482803");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1490561
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6a9565b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1492524
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5daf782e");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1492823
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?166aa054");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1493347
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a933cb35");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1495011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39935a02");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1495245
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5b58d2f");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1496159
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6925998");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1496340
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a31d3226");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498460
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f93877a1");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498482
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3a7cc16");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1498701
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef389f56");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1499198
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82d76ead");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-28/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?902c50a9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 60.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12391");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-12392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Thunderbird install is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'60.3', severity:SECURITY_HOLE);
