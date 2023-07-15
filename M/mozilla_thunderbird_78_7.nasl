## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-05.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(145468);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/04");

  script_cve_id(
    "CVE-2020-15685",
    "CVE-2020-26976",
    "CVE-2021-23953",
    "CVE-2021-23954",
    "CVE-2021-23960",
    "CVE-2021-23964"
  );

  script_name(english:"Mozilla Thunderbird < 78.7");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 78.7. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-05 advisory.

  - If a user clicked into a specifically crafted PDF, the PDF reader could be confused into leaking cross-
    origin information, when said information is served as chunked data. (CVE-2021-23953)

  - Using the new logical assignment operators in a JavaScript switch statement could have caused a type
    confusion, leading to a memory corruption and a potentially exploitable crash. (CVE-2021-23954)

  - During the plaintext phase of the STARTTLS connection setup, protocol commands could have been injected
    and evaluated within the encrypted session. (CVE-2020-15685)

  - When a HTTPS page was embedded in a HTTP page, and there was a service worker registered for the former,
    the service worker could have intercepted the request for the secure page despite the iframe not being a
    secure context due to the (insecure) framing. (CVE-2020-26976)

  - Performing garbage collection on re-declared JavaScript variables resulted in a user-after-poison, and a
    potentially exploitable crash. (CVE-2021-23960)

  - Mozilla developers Alexis Beingessner, Christian Holler, Andrew McCreight, Tyson Smith, Jon Coppeard,
    Andr Bargull, Jason Kratzer, Jesse Schwartzentruber, Steve Fink, Byron Campen reported memory safety bugs
    present in Thunderbird 78.6. Some of these bugs showed evidence of memory corruption and we presume that
    with enough effort some of these could have been exploited to run arbitrary code. (CVE-2021-23964)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-05/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 78.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23960");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'78.7', severity:SECURITY_WARNING);
