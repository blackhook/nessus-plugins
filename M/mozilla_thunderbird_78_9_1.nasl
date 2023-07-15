## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-13.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(148395);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id(
    "CVE-2021-23991",
    "CVE-2021-23992",
    "CVE-2021-23993",
    "CVE-2021-29949"
  );
  script_xref(name:"IAVA", value:"2021-A-0163-S");

  script_name(english:"Mozilla Thunderbird < 78.9.1");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 78.9.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2021-13 advisory.

  - If a Thunderbird user has previously imported Alice's OpenPGP key, and Alice has extended the validity
    period of her key, but Alice's updated key has not yet been imported, an attacker may send an email
    containing a crafted version of Alice's key with an invalid subkey, Thunderbird might subsequently attempt
    to use the invalid subkey, and will fail to send encrypted email to Alice. (CVE-2021-23991)

  - Thunderbird did not check if the user ID associated with an OpenPGP key has a valid self signature. An
    attacker may create a crafted version of an OpenPGP key, by either replacing the original user ID, or by
    adding another user ID. If Thunderbird imports and accepts the crafted key, the Thunderbird user may
    falsely conclude that the false user ID belongs to the correspondent. (CVE-2021-23992)

  - An attacker may perform a DoS attack to prevent a user from sending encrypted email to a correspondent. If
    an attacker creates a crafted OpenPGP key with a subkey that has an invalid self signature, and the
    Thunderbird user imports the crafted key, then Thunderbird may try to use the invalid subkey, but the RNP
    library rejects it from being used, causing encryption to fail. (CVE-2021-23993)

  - When loading the shared library that provides the OTR protocol implementation, Thunderbird will initially
    attempt to open it using a filename that isn't distributed by Thunderbird. If a computer has already been
    infected with a malicious library of the alternative filename, and the malicious library has been copied
    to a directory that is contained in the search path for executable libraries, then Thunderbird will load
    the incorrect library. (CVE-2021-29949)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 78.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29949");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'78.9.1', severity:SECURITY_WARNING);
