#
# (C) Tenable Network Security, Inc.
#



# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-34.
# The text itself is copyright (C) Mozilla Foundation.



include('compat.inc');

if (description)
{
  script_id(130170);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2018-6156",
    "CVE-2019-11757",
    "CVE-2019-11759",
    "CVE-2019-11760",
    "CVE-2019-11761",
    "CVE-2019-11762",
    "CVE-2019-11763",
    "CVE-2019-11764",
    "CVE-2019-11765",
    "CVE-2019-15903",
    "CVE-2019-17000",
    "CVE-2019-17001",
    "CVE-2019-17002"
  );
  script_bugtraq_id(104887);
  script_xref(name:"MFSA", value:"2019-34");
  script_xref(name:"IAVA", value:"2019-A-0395-S");

  script_name(english:"Mozilla Firefox < 70.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox ESR");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 70.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-34 advisory, including the following:

  - Incorrect derivation of a packet length in WebRTC in Google Chrome prior to 68.0.3440.75 allowed a remote
    attacker to potentially exploit heap corruption via a crafted video file. (CVE-2018-6156)

  - In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to
    document parsing too early; a consecutive call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber)
    then resulted in a heap-based buffer over-read. (CVE-2019-15903)

  - When storing a value in IndexedDB, the value's prototype chain is followed and it was possible to retain a
    reference to a locale, delete it, and subsequently reference it. This resulted in a use-after-free and a
    potentially exploitable crash. (CVE-2019-11757)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-34/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 70.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'70.0', severity:SECURITY_WARNING, xss:TRUE);

