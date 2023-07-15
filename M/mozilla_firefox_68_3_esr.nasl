#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-37.
# The text itself is copyright (C) Mozilla Foundation.


include('compat.inc');

if (description)
{
  script_id(131767);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/16");

  script_cve_id(
    "CVE-2019-11745",
    "CVE-2019-13722",
    "CVE-2019-17005",
    "CVE-2019-17008",
    "CVE-2019-17009",
    "CVE-2019-17010",
    "CVE-2019-17011",
    "CVE-2019-17012"
  );
  script_xref(name:"MFSA", value:"2019-37");

  script_name(english:"Mozilla Firefox ESR 68.x < 68.3 Multiple vulnerabilities");
  script_summary(english:"Checks version of Firefox ESR");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 68.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2019-37 advisory, including the following:

  - When encrypting with a block cipher, if a call to NSC_EncryptUpdate was made with data smaller than the
    block size, a small out of bounds write could occur. This could have caused heap corruption and a
    potentially exploitable crash. (CVE-2019-11745)

  - When using nested workers, a use-after-free could occur during worker destruction. This resulted in a
    potentially exploitable crash. (CVE-2019-17008)

  - Mozilla developers Christoph Diehl, Nathan Froyd, Jason Kratzer, Christian Holler, Karl Tomlinson, Tyson
    Smith reported memory safety bugs present in Firefox 70 and Firefox ESR 68.2. Some of these bugs showed
    evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2019-17012)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-37/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 68.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'68.3', min:'68.0.0', severity:SECURITY_WARNING);

