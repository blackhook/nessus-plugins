#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93661);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2016-5250",
    "CVE-2016-5257",
    "CVE-2016-5261",
    "CVE-2016-5270",
    "CVE-2016-5272",
    "CVE-2016-5274",
    "CVE-2016-5276",
    "CVE-2016-5277",
    "CVE-2016-5278",
    "CVE-2016-5280",
    "CVE-2016-5281",
    "CVE-2016-5284"
  );
  script_bugtraq_id(92260, 93049);
  script_xref(name:"MFSA", value:"2016-86");

  script_name(english:"Mozilla Firefox ESR 45.x < 45.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Windows
host is 45.x prior to 45.4. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in the HttpBaseChannel::GetPerformance()
    function in netwerk/protocol/http/HttpBaseChannel.cpp
    due to the program leaking potentially sensitive
    resources of URLs through the Resource Timing API
    during page navigation. An unauthenticated, remote
    attacker can exploit this to disclose sensitive
    information. (CVE-2016-5250)

  - Multiple memory safety issues exist that allow an
    unauthenticated, remote attacker to potentially execute
    arbitrary code. (CVE-2016-5257)

  - An integer overflow condition exists in the
    WebSocketChannel::ProcessInput() function within file
    netwerk/protocol/websocket/WebSocketChannel.cpp when
    handling specially crafted WebSocketChannel packets due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5261)

  - A heap buffer overflow condition exists in the
    nsCaseTransformTextRunFactory::TransformString()
    function in layout/generic/nsTextRunTransformations.cpp
    when converting text containing certain Unicode
    characters. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2016-5270)

  - A type confusion error exists within file
    layout/forms/nsRangeFrame.cpp when handling layout with
    input elements. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2016-5272)

  - A use-after-free error exists within file
    layout/style/nsRuleNode.cpp when handling web animations
    during restyling. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-5274)

  - A use-after-free error exists in the
    DocAccessible::ProcessInvalidationList() function within
    file accessible/generic/DocAccessible.cpp when setting
    an aria-owns attribute. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2016-5276)

  - A use-after-free error exists in the
    nsRefreshDriver::Tick() function when handling web
    animations destroying a timeline. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2016-5277)

  - A buffer overflow condition exists in the
    nsBMPEncoder::AddImageFrame() function within file
    dom/base/ImageEncoder.cpp when encoding image frames to
    images. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code. (CVE-2016-5278)

  - A use-after-free error exists in the
    nsTextNodeDirectionalityMap::RemoveElementFromMap()
    function within file dom/base/DirectionalityUtils.cpp
    when handling changing of text direction. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5280)

  - A use-after-free error exists when handling SVG format
    content that is being manipulated through script code.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5281)

  - A flaw exists due to the certificate pinning policy for
    built-in sites (e.g., addons.mozilla.org) not being
    honored when pins have expired. A man-in-the-middle
    (MitM) attacker can exploit this to generate a trusted
    certificate, which could be used to conduct spoofing
    attacks. (CVE-2016-5284)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-86/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 45.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'45.4', min:'45.0', severity:SECURITY_HOLE);
