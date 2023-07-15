#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-47.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154059);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-32810",
    "CVE-2021-38496",
    "CVE-2021-38497",
    "CVE-2021-38498",
    "CVE-2021-38500",
    "CVE-2021-38501",
    "CVE-2021-38502"
  );
  script_xref(name:"IAVA", value:"2021-A-0461-S");
  script_xref(name:"IAVA", value:"2021-A-0450-S");

  script_name(english:"Mozilla Thunderbird < 91.2");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 91.2. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-47 advisory.

  - Thunderbird ignored the configuration to require STARTTLS security for an SMTP connection. A MITM could
    perform a downgrade attack to intercept transmitted messages, or could take control of the authenticated
    session to execute SMTP commands chosen by the MITM. If an unprotected authentication method was
    configured, the MITM could obtain the authentication credentials, too. (CVE-2021-38502)

  - During operations on MessageTasks, a task may have been removed while it was still scheduled, resulting in
    memory corruption and a potentially exploitable crash. (CVE-2021-38496)

  - Through use of reportValidity() and window.open(), a plain-text validation
    message could have been overlaid on another origin, leading to possible user confusion and spoofing
    attacks. (CVE-2021-38497)

  - During process shutdown, a document could have caused a use-after-free of a languages service object,
    leading to memory corruption and a potentially exploitable crash. (CVE-2021-38498)

  - In the crossbeam crate, one or more tasks in the worker queue could have been be popped twice instead of
    other tasks that are forgotten and never popped. If tasks are allocated on the heap, this could have
    caused a double free and a memory leak. (CVE-2021-32810)

  - Mozilla developers and community members Andreas Pehrson and Christian Holler reported memory safety bugs
    present in Thunderbird 91.1. Some of these bugs showed evidence of memory corruption and we presume that
    with enough effort some of these could have been exploited to run arbitrary code. (CVE-2021-38500)

  - Mozilla developers and community members Kevin Brosnan, Mihai Alexandru Michis, and Christian Holler
    reported memory safety bugs present in Thunderbird 91.1. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code. (CVE-2021-38501)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-47/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 91.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38501");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-32810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'91.2', severity:SECURITY_WARNING);
