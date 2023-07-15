#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-36.
# The text itself is copyright (C) Mozilla Foundation.


include('compat.inc');

if (description)
{
  script_id(131773);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/16");

  script_cve_id(
    "CVE-2019-11745",
    "CVE-2019-11756",
    "CVE-2019-13722",
    "CVE-2019-17005",
    "CVE-2019-17008",
    "CVE-2019-17009",
    "CVE-2019-17010",
    "CVE-2019-17011",
    "CVE-2019-17012",
    "CVE-2019-17013",
    "CVE-2019-17014"
  );
  script_xref(name:"MFSA", value:"2019-36");

  script_name(english:"Mozilla Firefox < 71.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior
to 71.0. It is, therefore, affected by multiple vulnerabilities as
referenced in the mfsa2019-36 advisory.

  - When encrypting with a block cipher, if a call to 
    NSC_EncryptUpdate was made with data smaller than the block 
    size, a small out of bounds write could occur. This could 
    have caused heap corruption and a potentially exploitable 
    crash. (CVE-2019-11745)

  - Improper refcounting of soft token session objects could 
    cause a use-after-free and crash (likely limited to a denial 
    of service). (CVE-2019-11756)

  - When setting a thread name on Windows in WebRTC, an 
    incorrect number of arguments could have been supplied, 
    leading to stack corruption and a potentially exploitable 
    crash.
    Note: this issue only occurs on Windows. Other operating 
    systems are unaffected. (CVE-2019-13722)

  - When using nested workers, a use-after-free could occur 
    during worker destruction. This resulted in a potentially
    exploitable crash. (CVE-2019-17008)

  - When running, the updater service wrote status and log 
    files to an unrestricted location; potentially allowing 
    an unprivileged process to locate and exploit a 
    vulnerability in file handling in the updater service.
  - Note: This attack requires local system access and only 
    affects Windows. Other operating systems are not affected.
    (CVE-2019-17009)

  - Under certain conditions, when checking the Resist 
    Fingerprinting preference during device orientation checks, 
    a race condition could have caused a use-after-free and a
    potentially exploitable crash. (CVE-2019-17010)

  - Under certain conditions, when retrieving a document from 
    a DocShell in the antitracking code, a race condition 
    could cause a use-after-free condition and a potentially 
    exploitable crash. (CVE-2019-17011)

  - Mozilla developers Christoph Diehl, Nathan Froyd, Jason 
    Kratzer, Christian Holler, Karl Tomlinson, Tyson Smith 
    reported memory safety bugs present in Firefox 70 and 
    Firefox ESR 68.2. Some of these bugs showed evidence of 
    memory corruption and we presume that with enough effort 
    some of these could have been exploited to run arbitrary code.
    (CVE-2019-17012)

  - Mozilla developers and community members Philipp, Diego 
    Calleja, Mikhail Gavrilov, Jason Kratzer, Christian 
    Holler, Markus Stange, Tyson Smith reported memory safety 
    bugs present in Firefox 70. Some of these bugs showed 
    evidence of memory corruption and we presume that with 
    enough effort some of these could have been exploited to 
    run arbitrary code. (CVE-2019-17013)

  - If an image had not loaded correctly (such as when it is 
    not actually an image), it could be dragged and dropped 
    cross-domain, resulting in a cross-origin information leak.
    (CVE-2019-17014)
    
Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-36/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 71.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'71.0', severity:SECURITY_WARNING);

