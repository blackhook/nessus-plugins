#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202201-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157241);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id(
    "CVE-2021-4098",
    "CVE-2021-4099",
    "CVE-2021-4100",
    "CVE-2021-4101",
    "CVE-2021-4102",
    "CVE-2021-30565",
    "CVE-2021-30566",
    "CVE-2021-30567",
    "CVE-2021-30568",
    "CVE-2021-30569",
    "CVE-2021-30571",
    "CVE-2021-30572",
    "CVE-2021-30573",
    "CVE-2021-30574",
    "CVE-2021-30575",
    "CVE-2021-30576",
    "CVE-2021-30577",
    "CVE-2021-30578",
    "CVE-2021-30579",
    "CVE-2021-30580",
    "CVE-2021-30581",
    "CVE-2021-30582",
    "CVE-2021-30583",
    "CVE-2021-30584",
    "CVE-2021-30585",
    "CVE-2021-30586",
    "CVE-2021-30587",
    "CVE-2021-30588",
    "CVE-2021-30589",
    "CVE-2021-30590",
    "CVE-2021-30591",
    "CVE-2021-30592",
    "CVE-2021-30593",
    "CVE-2021-30594",
    "CVE-2021-30596",
    "CVE-2021-30597",
    "CVE-2021-30598",
    "CVE-2021-30599",
    "CVE-2021-30600",
    "CVE-2021-30601",
    "CVE-2021-30602",
    "CVE-2021-30603",
    "CVE-2021-30604",
    "CVE-2021-30606",
    "CVE-2021-30607",
    "CVE-2021-30608",
    "CVE-2021-30609",
    "CVE-2021-30610",
    "CVE-2021-30611",
    "CVE-2021-30612",
    "CVE-2021-30613",
    "CVE-2021-30614",
    "CVE-2021-30615",
    "CVE-2021-30616",
    "CVE-2021-30617",
    "CVE-2021-30618",
    "CVE-2021-30619",
    "CVE-2021-30620",
    "CVE-2021-30621",
    "CVE-2021-30622",
    "CVE-2021-30623",
    "CVE-2021-30624",
    "CVE-2021-30625",
    "CVE-2021-30626",
    "CVE-2021-30627",
    "CVE-2021-30628",
    "CVE-2021-30629",
    "CVE-2021-30630",
    "CVE-2021-30631",
    "CVE-2021-30632",
    "CVE-2021-30633",
    "CVE-2021-37956",
    "CVE-2021-37957",
    "CVE-2021-37958",
    "CVE-2021-37959",
    "CVE-2021-37960",
    "CVE-2021-37961",
    "CVE-2021-37962",
    "CVE-2021-37963",
    "CVE-2021-37965",
    "CVE-2021-37966",
    "CVE-2021-37967",
    "CVE-2021-37968",
    "CVE-2021-37970",
    "CVE-2021-37971",
    "CVE-2021-37973",
    "CVE-2021-37974",
    "CVE-2021-37975",
    "CVE-2021-37976",
    "CVE-2021-37977",
    "CVE-2021-37978",
    "CVE-2021-37979",
    "CVE-2021-37981",
    "CVE-2021-37982",
    "CVE-2021-37983",
    "CVE-2021-37984",
    "CVE-2021-37985",
    "CVE-2021-37986",
    "CVE-2021-37987",
    "CVE-2021-37988",
    "CVE-2021-37989",
    "CVE-2021-37990",
    "CVE-2021-37991",
    "CVE-2021-37992",
    "CVE-2021-37993",
    "CVE-2021-37994",
    "CVE-2021-37995",
    "CVE-2021-37996",
    "CVE-2021-37997",
    "CVE-2021-37998",
    "CVE-2021-37999",
    "CVE-2021-38000",
    "CVE-2021-38001",
    "CVE-2021-38002",
    "CVE-2021-38003",
    "CVE-2021-38005",
    "CVE-2021-38006",
    "CVE-2021-38007",
    "CVE-2021-38008",
    "CVE-2021-38009",
    "CVE-2021-38010",
    "CVE-2021-38011",
    "CVE-2021-38012",
    "CVE-2021-38013",
    "CVE-2021-38014",
    "CVE-2021-38015",
    "CVE-2021-38016",
    "CVE-2021-38017",
    "CVE-2021-38018",
    "CVE-2021-38019",
    "CVE-2021-38020",
    "CVE-2021-38021",
    "CVE-2021-38022",
    "CVE-2022-0096",
    "CVE-2022-0097",
    "CVE-2022-0098",
    "CVE-2022-0099",
    "CVE-2022-0100",
    "CVE-2022-0101",
    "CVE-2022-0102",
    "CVE-2022-0103",
    "CVE-2022-0104",
    "CVE-2022-0105",
    "CVE-2022-0106",
    "CVE-2022-0107",
    "CVE-2022-0108",
    "CVE-2022-0109",
    "CVE-2022-0110",
    "CVE-2022-0111",
    "CVE-2022-0112",
    "CVE-2022-0113",
    "CVE-2022-0114",
    "CVE-2022-0115",
    "CVE-2022-0116",
    "CVE-2022-0117",
    "CVE-2022-0118",
    "CVE-2022-0120",
    "CVE-2022-0289",
    "CVE-2022-0290",
    "CVE-2022-0291",
    "CVE-2022-0292",
    "CVE-2022-0293",
    "CVE-2022-0294",
    "CVE-2022-0295",
    "CVE-2022-0296",
    "CVE-2022-0297",
    "CVE-2022-0298",
    "CVE-2022-0300",
    "CVE-2022-0301",
    "CVE-2022-0302",
    "CVE-2022-0303",
    "CVE-2022-0304",
    "CVE-2022-0305",
    "CVE-2022-0306",
    "CVE-2022-0307",
    "CVE-2022-0308",
    "CVE-2022-0309",
    "CVE-2022-0310",
    "CVE-2022-0311"
  );
  script_xref(name:"IAVA", value:"2021-A-0346-S");
  script_xref(name:"IAVA", value:"2021-A-0361-S");
  script_xref(name:"IAVA", value:"2021-A-0385-S");
  script_xref(name:"IAVA", value:"2021-A-0401-S");
  script_xref(name:"IAVA", value:"2021-A-0411-S");
  script_xref(name:"IAVA", value:"2021-A-0438-S");
  script_xref(name:"IAVA", value:"2021-A-0448-S");
  script_xref(name:"IAVA", value:"2021-A-0449-S");
  script_xref(name:"IAVA", value:"2021-A-0459-S");
  script_xref(name:"IAVA", value:"2021-A-0491-S");
  script_xref(name:"IAVA", value:"2021-A-0522-S");
  script_xref(name:"IAVA", value:"2021-A-0555-S");
  script_xref(name:"IAVA", value:"2021-A-0576-S");
  script_xref(name:"IAVA", value:"2022-A-0001-S");
  script_xref(name:"IAVA", value:"2022-A-0042-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/29");

  script_name(english:"GLSA-202201-02 : Chromium, Google Chrome: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202201-02 (Chromium, Google Chrome: Multiple
vulnerabilities)

  - Out of bounds write in Tab Groups in Google Chrome on Linux and ChromeOS prior to 92.0.4515.107 allowed an
    attacker who convinced a user to install a malicious extension to perform an out of bounds memory write
    via a crafted HTML page. (CVE-2021-30565)

  - Stack buffer overflow in Printing in Google Chrome prior to 92.0.4515.107 allowed a remote attacker who
    had compromised the renderer process to potentially exploit stack corruption via a crafted HTML page.
    (CVE-2021-30566)

  - Use after free in DevTools in Google Chrome prior to 92.0.4515.107 allowed an attacker who convinced a
    user to open DevTools to potentially exploit heap corruption via specific user gesture. (CVE-2021-30567)

  - Heap buffer overflow in WebGL in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30568)

  - Use after free in sqlite in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30569)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 92.0.4515.107 allowed an attacker
    who convinced a user to install a malicious extension to potentially perform a sandbox escape via a
    crafted HTML page. (CVE-2021-30571)

  - Use after free in Autofill in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30572)

  - Use after free in GPU in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30573)

  - Use after free in protocol handling in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30574)

  - Out of bounds write in Autofill in Google Chrome prior to 92.0.4515.107 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30575)

  - Use after free in DevTools in Google Chrome prior to 92.0.4515.107 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30576, CVE-2021-30581)

  - Insufficient policy enforcement in Installer in Google Chrome prior to 92.0.4515.107 allowed a remote
    attacker to perform local privilege escalation via a crafted file. (CVE-2021-30577)

  - Uninitialized use in Media in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to perform
    out of bounds memory access via a crafted HTML page. (CVE-2021-30578)

  - Use after free in UI framework in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30579)

  - Insufficient policy enforcement in Android intents in Google Chrome prior to 92.0.4515.107 allowed an
    attacker who convinced a user to install a malicious application to obtain potentially sensitive
    information via a crafted HTML page. (CVE-2021-30580)

  - Inappropriate implementation in Animation in Google Chrome prior to 92.0.4515.107 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-30582)

  - Insufficient policy enforcement in image handling in iOS in Google Chrome on iOS prior to 92.0.4515.107
    allowed a remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-30583)

  - Incorrect security UI in Downloads in Google Chrome on Android prior to 92.0.4515.107 allowed a remote
    attacker to perform domain spoofing via a crafted HTML page. (CVE-2021-30584)

  - Use after free in sensor handling in Google Chrome on Windows prior to 92.0.4515.107 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30585)

  - Use after free in dialog box handling in Windows in Google Chrome prior to 92.0.4515.107 allowed an
    attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via
    a crafted HTML page. (CVE-2021-30586)

  - Inappropriate implementation in Compositing in Google Chrome prior to 92.0.4515.107 allowed a remote
    attacker to potentially spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2021-30587)

  - Type confusion in V8 in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30588)

  - Insufficient validation of untrusted input in Sharing in Google Chrome prior to 92.0.4515.107 allowed a
    remote attacker to bypass navigation restrictions via a crafted click-to-call link. (CVE-2021-30589)

  - Heap buffer overflow in Bookmarks in Google Chrome prior to 92.0.4515.131 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30590)

  - Use after free in File System API in Google Chrome prior to 92.0.4515.131 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30591)

  - Out of bounds write in Tab Groups in Google Chrome prior to 92.0.4515.131 allowed an attacker who
    convinced a user to install a malicious extension to perform an out of bounds memory write via a crafted
    HTML page. (CVE-2021-30592)

  - Out of bounds read in Tab Strip in Google Chrome prior to 92.0.4515.131 allowed an attacker who convinced
    a user to install a malicious extension to perform an out of bounds memory read via a crafted HTML page.
    (CVE-2021-30593)

  - Use after free in Page Info UI in Google Chrome prior to 92.0.4515.131 allowed a remote attacker to
    potentially exploit heap corruption via physical access to the device. (CVE-2021-30594)

  - Incorrect security UI in Navigation in Google Chrome on Android prior to 92.0.4515.131 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-30596)

  - Use after free in Browser UI in Google Chrome on Chrome prior to 92.0.4515.131 allowed a remote attacker
    to potentially exploit heap corruption via physical access to the device. (CVE-2021-30597)

  - Type confusion in V8 in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to execute
    arbitrary code inside a sandbox via a crafted HTML page. (CVE-2021-30598, CVE-2021-30599)

  - Use after free in Printing in Google Chrome prior to 92.0.4515.159 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30600)

  - Use after free in Extensions API in Google Chrome prior to 92.0.4515.159 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30601)

  - Use after free in WebRTC in Google Chrome prior to 92.0.4515.159 allowed an attacker who convinced a user
    to visit a malicious website to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30602)

  - Data race in WebAudio in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30603)

  - Use after free in ANGLE in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30604)

  - Chromium: CVE-2021-30606 Use after free in Blink (CVE-2021-30606)

  - Chromium: CVE-2021-30607 Use after free in Permissions (CVE-2021-30607)

  - Chromium: CVE-2021-30608 Use after free in Web Share (CVE-2021-30608)

  - Chromium: CVE-2021-30609 Use after free in Sign-In (CVE-2021-30609)

  - Chromium: CVE-2021-30610 Use after free in Extensions API (CVE-2021-30610)

  - Chromium: CVE-2021-30611 Use after free in WebRTC (CVE-2021-30611)

  - Chromium: CVE-2021-30612 Use after free in WebRTC (CVE-2021-30612)

  - Chromium: CVE-2021-30613 Use after free in Base internals (CVE-2021-30613)

  - Chromium: CVE-2021-30614 Heap buffer overflow in TabStrip (CVE-2021-30614)

  - Chromium: CVE-2021-30615 Cross-origin data leak in Navigation (CVE-2021-30615)

  - Chromium: CVE-2021-30616 Use after free in Media (CVE-2021-30616)

  - Chromium: CVE-2021-30617 Policy bypass in Blink (CVE-2021-30617)

  - Chromium: CVE-2021-30618 Inappropriate implementation in DevTools (CVE-2021-30618)

  - Chromium: CVE-2021-30619 UI Spoofing in Autofill (CVE-2021-30619)

  - Chromium: CVE-2021-30620 Insufficient policy enforcement in Blink (CVE-2021-30620)

  - Chromium: CVE-2021-30621 UI Spoofing in Autofill (CVE-2021-30621)

  - Chromium: CVE-2021-30622 Use after free in WebApp Installs (CVE-2021-30622)

  - Chromium: CVE-2021-30623 Use after free in Bookmarks (CVE-2021-30623)

  - Chromium: CVE-2021-30624 Use after free in Autofill (CVE-2021-30624)

  - Use after free in Selection API in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who
    convinced the user the visit a malicious website to potentially exploit heap corruption via a crafted HTML
    page. (CVE-2021-30625)

  - Out of bounds memory access in ANGLE in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30626)

  - Type confusion in Blink layout in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30627)

  - Stack buffer overflow in ANGLE in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit stack corruption via a crafted HTML page. (CVE-2021-30628)

  - Use after free in Permissions in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30629)

  - Inappropriate implementation in Blink in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who
    had compromised the renderer process to leak cross-origin data via a crafted HTML page. (CVE-2021-30630)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by
    its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2021-30631,
    CVE-2021-37960)

  - Out of bounds write in V8 in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30632)

  - Use after free in Indexed DB API in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-30633)

  - Use after free in Offline use in Google Chrome on Android prior to 94.0.4606.54 allowed a remote attacker
    who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37956)

  - Use after free in WebGPU in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-37957)

  - Inappropriate implementation in Navigation in Google Chrome on Windows prior to 94.0.4606.54 allowed a
    remote attacker to inject scripts or HTML into a privileged page via a crafted HTML page. (CVE-2021-37958)

  - Use after free in Task Manager in Google Chrome prior to 94.0.4606.54 allowed an attacker who convinced a
    user to enage in a series of user gestures to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37959)

  - Use after free in Tab Strip in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37961)

  - Use after free in Performance Manager in Google Chrome prior to 94.0.4606.54 allowed a remote attacker who
    had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37962)

  - Side-channel information leakage in DevTools in Google Chrome prior to 94.0.4606.54 allowed a remote
    attacker to bypass site isolation via a crafted HTML page. (CVE-2021-37963)

  - Inappropriate implementation in Background Fetch API in Google Chrome prior to 94.0.4606.54 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-37965, CVE-2021-37968)

  - Inappropriate implementation in Compositing in Google Chrome on Android prior to 94.0.4606.54 allowed a
    remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-37966)

  - Inappropriate implementation in Background Fetch API in Google Chrome prior to 94.0.4606.54 allowed a
    remote attacker who had compromised the renderer process to leak cross-origin data via a crafted HTML
    page. (CVE-2021-37967)

  - Use after free in File System API in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37970)

  - Incorrect security UI in Web Browser UI in Google Chrome prior to 94.0.4606.54 allowed a remote attacker
    to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-37971)

  - Use after free in Portals in Google Chrome prior to 94.0.4606.61 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-37973)

  - Use after free in Safebrowsing in Google Chrome prior to 94.0.4606.71 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37974)

  - Use after free in V8 in Google Chrome prior to 94.0.4606.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-37975)

  - Inappropriate implementation in Memory in Google Chrome prior to 94.0.4606.71 allowed a remote attacker to
    obtain potentially sensitive information from process memory via a crafted HTML page. (CVE-2021-37976)

  - Use after free in Garbage Collection in Google Chrome prior to 94.0.4606.81 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37977)

  - Heap buffer overflow in Blink in Google Chrome prior to 94.0.4606.81 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37978)

  - heap buffer overflow in WebRTC in Google Chrome prior to 94.0.4606.81 allowed a remote attacker who
    convinced a user to browse to a malicious website to potentially exploit heap corruption via a crafted
    HTML page. (CVE-2021-37979)

  - Heap buffer overflow in Skia in Google Chrome prior to 95.0.4638.54 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-37981)

  - Use after free in Incognito in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37982)

  - Use after free in Dev Tools in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37983)

  - Heap buffer overflow in PDFium in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37984)

  - Use after free in V8 in Google Chrome prior to 95.0.4638.54 allowed a remote attacker who had convinced a
    user to allow for connection to debugger to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37985)

  - Heap buffer overflow in Settings in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    engage with Dev Tools to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37986)

  - Use after free in Network APIs in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37987)

  - Use after free in Profiles in Google Chrome prior to 95.0.4638.54 allowed a remote attacker who convinced
    a user to engage in specific gestures to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-37988)

  - Inappropriate implementation in Blink in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    abuse content security policy via a crafted HTML page. (CVE-2021-37989)

  - Inappropriate implementation in WebView in Google Chrome on Android prior to 95.0.4638.54 allowed a remote
    attacker to leak cross-origin data via a crafted app. (CVE-2021-37990)

  - Race in V8 in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to potentially exploit heap
    corruption via a crafted HTML page. (CVE-2021-37991)

  - Out of bounds read in WebAudio in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37992)

  - Use after free in PDF Accessibility in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37993)

  - Inappropriate implementation in iFrame Sandbox in Google Chrome prior to 95.0.4638.54 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2021-37994)

  - Inappropriate implementation in WebApp Installer in Google Chrome prior to 95.0.4638.54 allowed a remote
    attacker to potentially overlay and spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2021-37995)

  - Insufficient validation of untrusted input Downloads in Google Chrome prior to 95.0.4638.54 allowed a
    remote attacker to bypass navigation restrictions via a malicious file. (CVE-2021-37996)

  - Use after free in Sign-In in Google Chrome prior to 95.0.4638.69 allowed a remote attacker who convinced a
    user to sign into Chrome to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37997)

  - Use after free in Garbage Collection in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37998)

  - Insufficient data validation in New Tab Page in Google Chrome prior to 95.0.4638.69 allowed a remote
    attacker to inject arbitrary scripts or HTML in a new browser tab via a crafted HTML page.
    (CVE-2021-37999)

  - Insufficient validation of untrusted input in Intents in Google Chrome on Android prior to 95.0.4638.69
    allowed a remote attacker to arbitrarily browser to a malicious URL via a crafted HTML page.
    (CVE-2021-38000)

  - Type confusion in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38001)

  - Use after free in Web Transport in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2021-38002)

  - Inappropriate implementation in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38003)

  - Use after free in loader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38005)

  - Use after free in storage foundation in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38006, CVE-2021-38011)

  - Type confusion in V8 in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38007, CVE-2021-38012)

  - Use after free in media in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38008)

  - Inappropriate implementation in cache in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (CVE-2021-38009)

  - Inappropriate implementation in service workers in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker who had compromised the renderer process to bypass site isolation via a crafted HTML page.
    (CVE-2021-38010)

  - Heap buffer overflow in fingerprint recognition in Google Chrome on ChromeOS prior to 96.0.4664.45 allowed
    a remote attacker who had compromised a WebUI renderer process to potentially perform a sandbox escape via
    a crafted HTML page. (CVE-2021-38013)

  - Out of bounds write in Swiftshader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38014)

  - Inappropriate implementation in input in Google Chrome prior to 96.0.4664.45 allowed an attacker who
    convinced a user to install a malicious extension to bypass navigation restrictions via a crafted Chrome
    Extension. (CVE-2021-38015)

  - Insufficient policy enforcement in background fetch in Google Chrome prior to 96.0.4664.45 allowed a
    remote attacker to bypass same origin policy via a crafted HTML page. (CVE-2021-38016)

  - Insufficient policy enforcement in iframe sandbox in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2021-38017)

  - Inappropriate implementation in navigation in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to perform domain spoofing via a crafted HTML page. (CVE-2021-38018)

  - Insufficient policy enforcement in CORS in Google Chrome prior to 96.0.4664.45 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (CVE-2021-38019)

  - Insufficient policy enforcement in contacts picker in Google Chrome on Android prior to 96.0.4664.45
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2021-38020)

  - Inappropriate implementation in referrer in Google Chrome prior to 96.0.4664.45 allowed a remote attacker
    to bypass navigation restrictions via a crafted HTML page. (CVE-2021-38021)

  - Inappropriate implementation in WebAuthentication in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-38022)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202201-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803167");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=806223");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=808715");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=811348");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=813035");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=814221");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=814617");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=815673");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=816984");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=819054");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=820689");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=824274");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829190");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=830642");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831624");
  script_set_attribute(attribute:"solution", value:
"All Chromium users should upgrade to the latest version:

			# emerge --sync
			# emerge --ask --oneshot --verbose
			>=www-client/chromium-97.0.4692.99
		
All Google Chrome users should upgrade to the latest version:

			# emerge --sync
			# emerge --ask --oneshot --verbose
			>=www-client/google-chrome-97.0.4692.99");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "www-client/google-chrome",
    'unaffected' : make_list("ge 97.0.4692.99"),
    'vulnerable' : make_list("lt 97.0.4692.99")
  },
  {
    'name' : "www-client/chromium",
    'unaffected' : make_list("ge 97.0.4692.99"),
    'vulnerable' : make_list("lt 97.0.4692.99")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome");
}
