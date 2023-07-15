#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2018-23.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(117669);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-12383", "CVE-2018-12385");

  script_name(english:"Mozilla Firefox ESR < 60.2.1 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox ESR.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote macOS host
is prior to 60.2.1. It is, therefore, affected by multiple
vulnerabilities :

  - A potentially exploitable crash in TransportSecurityInfo used for
    SSL can be triggered by data stored in the local cache in the user
    profile directory. This issue is only exploitable in combination
    with another vulnerability allowing an attacker to write data into
    the local cache or from locally installed malware. This issue also
    triggers a non-exploitable startup crash for users switching
    between the Nightly and Release versions of Firefox if the same
    profile is used. (CVE-2018-12385)

  - If a user saved passwords before Firefox 58 and then later set a
    master password, an unencrypted copy of these passwords is still
    accessible. This is because the older stored password file was not
    deleted when the data was copied to a new format starting in
    Firefox 58. The new master password is added only on the new file.
    This could allow the exposure of stored password data outside of
    user expectations. (CVE-2018-12383)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1475775
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc528cf5");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1490585
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7fa8df5");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-23/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?082e6c8c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 60.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/24");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'60.2.1', min:'60.0', severity:SECURITY_WARNING);
