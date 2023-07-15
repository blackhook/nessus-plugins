#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-03.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(121599);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2016-5824",
    "CVE-2018-18500",
    "CVE-2018-18501",
    "CVE-2018-18505",
    "CVE-2018-18512",
    "CVE-2018-18513"
  );
  script_xref(name:"MFSA", value:"2019-03");

  script_name(english:"Mozilla Thunderbird < 60.5");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X
host is prior to 60.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-03 advisory.

  - A use-after-free vulnerability can occur while parsing
    an HTML5 stream in concert with custom HTML elements.
    This results in the stream parser object being freed
    while still in use, leading to a potentially exploitable
    crash. (CVE-2018-18500)

  - An earlier fix for an Inter-process Communication (IPC)
    vulnerability, CVE-2011-3079, added authentication to
    communication between IPC endpoints and server parents
    during IPC process creation. This authentication is
    insufficient for channels created after the IPC process
    is started, leading to the authentication not being
    correctly applied to later channels. This could allow
    for a sandbox escape through IPC channels due to lack of
    message validation in the listener process.
    (CVE-2018-18505)

  - A vulnerability in the Libical libary used by
    Thunderbird can allow remote attackers to cause a denial
    of service (use-after-free) via a crafted ICS calendar
    file. (CVE-2016-5824)

  - Mozilla developers and community members Alex Gaynor,
    Christoph Diehl, Steven Crane, Jason Kratzer, Gary
    Kwong, and Christian Holler reported memory safety bugs
    present in Firefox 64, Firefox ESR 60.4, and Thunderbird
    60.4. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort that
    some of these could be exploited to run arbitrary code.
    (CVE-2018-18501)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-03/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1510114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1497749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1087565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1275400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1512450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1517542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1513201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1460619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1502871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1516738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1516514");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 60.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18512");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18505");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'60.5', severity:SECURITY_HOLE);
