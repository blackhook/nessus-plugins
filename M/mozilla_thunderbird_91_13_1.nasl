#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-39.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(165245);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/04");

  script_cve_id("CVE-2022-3032", "CVE-2022-3033", "CVE-2022-3034");
  script_xref(name:"IAVA", value:"2022-A-0349-S");

  script_name(english:"Mozilla Thunderbird < 91.13.1");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 91.13.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2022-39 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-39/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 91.13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3033");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'91.13.1', severity:SECURITY_HOLE);
