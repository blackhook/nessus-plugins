#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-38.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(164540);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/04");

  script_cve_id(
    "CVE-2022-3032",
    "CVE-2022-3033",
    "CVE-2022-3034",
    "CVE-2022-36059"
  );
  script_xref(name:"IAVA", value:"2022-A-0349-S");

  script_name(english:"Mozilla Thunderbird < 102.2.1");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote macOS or Mac OS X host is prior to 102.2.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the mfsa2022-38 advisory.

  - If a Thunderbird user replied to a crafted HTML email containing a <code>meta</code> tag, with the
    <code>meta</code> tag having the <code>http-equiv=refresh</code> attribute, and the content attribute
    specifying an URL, then Thunderbird started a network request to that URL, regardless of the configuration
    to block remote content. In combination with certain other HTML elements and attributes in the email, it
    was possible to execute JavaScript code included in the message in the context of the message compose
    document.  The JavaScript code was able to perform actions including, but probably not limited to, read
    and modify the contents of the message compose document, including the quoted original message, which
    could potentially contain the decrypted plaintext of encrypted data  in the crafted email. The contents
    could then be transmitted to the network, either to the URL specified in the META refresh tag, or to a
    different URL, as the JavaScript code could modify the URL specified in the document. This bug doesn't
    affect users who have changed the default Message Body display setting to 'simple html' or 'plain text'.
    (CVE-2022-3033)

  - When receiving an HTML email that contained an <code>iframe</code> element, which used a
    <code>srcdoc</code> attribute to define the inner HTML document, remote objects specified in the nested
    document, for example images or videos, were not blocked. Rather, the network was accessed, the objects
    were loaded and displayed. (CVE-2022-3032)

  - When receiving an HTML email that specified to load an <code>iframe</code> element from a remote location,
    a request to the remote document was sent. However, Thunderbird didn't display the document.
    (CVE-2022-3034)

  - Thunderbird users who use the Matrix chat protocol were vulnerable to a denial-of-service attack. An
    adversary sharing a room with a user had the ability to carry out an attack against affected clients,
    making it not show all of a user's rooms or spaces and/or causing minor temporary corruption.
    (CVE-2022-36059)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-38/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 102.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3033");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Thunderbird';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Thunderbird installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'thunderbird', esr:FALSE, fix:'102.2.1', severity:SECURITY_HOLE);
