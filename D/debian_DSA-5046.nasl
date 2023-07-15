#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5046. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156763);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-4052",
    "CVE-2021-4053",
    "CVE-2021-4054",
    "CVE-2021-4055",
    "CVE-2021-4056",
    "CVE-2021-4057",
    "CVE-2021-4058",
    "CVE-2021-4059",
    "CVE-2021-4061",
    "CVE-2021-4062",
    "CVE-2021-4063",
    "CVE-2021-4064",
    "CVE-2021-4065",
    "CVE-2021-4066",
    "CVE-2021-4067",
    "CVE-2021-4068",
    "CVE-2021-4078",
    "CVE-2021-4079",
    "CVE-2021-4098",
    "CVE-2021-4099",
    "CVE-2021-4100",
    "CVE-2021-4101",
    "CVE-2021-4102",
    "CVE-2021-37956",
    "CVE-2021-37957",
    "CVE-2021-37958",
    "CVE-2021-37959",
    "CVE-2021-37961",
    "CVE-2021-37962",
    "CVE-2021-37963",
    "CVE-2021-37964",
    "CVE-2021-37965",
    "CVE-2021-37966",
    "CVE-2021-37967",
    "CVE-2021-37968",
    "CVE-2021-37969",
    "CVE-2021-37970",
    "CVE-2021-37971",
    "CVE-2021-37972",
    "CVE-2021-37973",
    "CVE-2021-37974",
    "CVE-2021-37975",
    "CVE-2021-37976",
    "CVE-2021-37977",
    "CVE-2021-37978",
    "CVE-2021-37979",
    "CVE-2021-37980",
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
    "CVE-2021-38004",
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
    "CVE-2022-0120"
  );
  script_xref(name:"IAVA", value:"2021-A-0438-S");
  script_xref(name:"IAVA", value:"2021-A-0448-S");
  script_xref(name:"IAVA", value:"2021-A-0449-S");
  script_xref(name:"IAVA", value:"2021-A-0459-S");
  script_xref(name:"IAVA", value:"2021-A-0491-S");
  script_xref(name:"IAVA", value:"2021-A-0522-S");
  script_xref(name:"IAVA", value:"2021-A-0555-S");
  script_xref(name:"IAVA", value:"2021-A-0568-S");
  script_xref(name:"IAVA", value:"2021-A-0576-S");
  script_xref(name:"IAVA", value:"2022-A-0001-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/29");

  script_name(english:"Debian DSA-5046-1 : chromium - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5046 advisory.

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

  - Inappropriate implementation in ChromeOS Networking in Google Chrome on ChromeOS prior to 94.0.4606.54
    allowed an attacker with a rogue wireless access point to to potentially carryout a wifi impersonation
    attack via a crafted ONC file. (CVE-2021-37964)

  - Inappropriate implementation in Background Fetch API in Google Chrome prior to 94.0.4606.54 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-37965, CVE-2021-37968)

  - Inappropriate implementation in Compositing in Google Chrome on Android prior to 94.0.4606.54 allowed a
    remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-37966)

  - Inappropriate implementation in Background Fetch API in Google Chrome prior to 94.0.4606.54 allowed a
    remote attacker who had compromised the renderer process to leak cross-origin data via a crafted HTML
    page. (CVE-2021-37967)

  - Inappropriate implementation in Google Updater in Google Chrome on Windows prior to 94.0.4606.54 allowed a
    remote attacker to perform local privilege escalation via a crafted file. (CVE-2021-37969)

  - Use after free in File System API in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37970)

  - Incorrect security UI in Web Browser UI in Google Chrome prior to 94.0.4606.54 allowed a remote attacker
    to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-37971)

  - Out of bounds read in libjpeg-turbo in Google Chrome prior to 94.0.4606.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37972)

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

  - Inappropriate implementation in Sandbox in Google Chrome prior to 94.0.4606.81 allowed a remote attacker
    to potentially bypass site isolation via Windows. (CVE-2021-37980)

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

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 95.0.4638.69 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-38004)

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

  - Use after free in web apps in Google Chrome prior to 96.0.4664.93 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (CVE-2021-4052)

  - Use after free in UI in Google Chrome on Linux prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4053)

  - Incorrect security UI in autofill in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    perform domain spoofing via a crafted HTML page. (CVE-2021-4054)

  - Heap buffer overflow in extensions in Google Chrome prior to 96.0.4664.93 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension. (CVE-2021-4055)

  - Type confusion in loader in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4056)

  - Use after free in file API in Google Chrome prior to 96.0.4664.93 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-4057)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4058)

  - Insufficient data validation in loader in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (CVE-2021-4059)

  - Type confusion in V8 in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4061, CVE-2021-4078)

  - Heap buffer overflow in BFCache in Google Chrome prior to 96.0.4664.93 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-4062)

  - Use after free in developer tools in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4063)

  - Use after free in screen capture in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4064)

  - Use after free in autofill in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4065)

  - Integer underflow in ANGLE in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-4066)

  - Use after free in window manager in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4067)

  - Insufficient data validation in new tab page in Google Chrome prior to 96.0.4664.93 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-4068)

  - Out of bounds write in WebRTC in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via crafted WebRTC packets. (CVE-2021-4079)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/chromium");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5046");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37956");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37957");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37958");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37959");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37961");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37962");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37963");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37964");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37965");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37966");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37967");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37968");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37969");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37970");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37971");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37972");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37973");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37975");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37976");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37977");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37978");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37979");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37980");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37982");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37983");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37984");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37985");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37986");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37987");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37988");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37990");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37991");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37992");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37993");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37994");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37995");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37997");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37999");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38000");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38002");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38003");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38004");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38005");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38006");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38007");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38008");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38009");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38010");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38011");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38012");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38013");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38014");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38015");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38017");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38018");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38020");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38021");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38022");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4052");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4053");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4054");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4055");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4056");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4057");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4059");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4062");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4063");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4064");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4065");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4066");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4067");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4068");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4078");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4079");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4100");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4101");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4102");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0097");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0100");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0101");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0102");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0103");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0104");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0105");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0106");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0107");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0108");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0109");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0110");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0111");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0112");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0113");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0115");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0116");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0117");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0118");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0120");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/chromium");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/chromium");
  script_set_attribute(attribute:"solution", value:
"Upgrade the chromium packages.

For the stable distribution (bullseye), these problems have been fixed in version 97.0.4692.71-0.1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0115");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0097");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'chromium', 'reference': '97.0.4692.71-0.1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-common', 'reference': '97.0.4692.71-0.1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-driver', 'reference': '97.0.4692.71-0.1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-l10n', 'reference': '97.0.4692.71-0.1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-sandbox', 'reference': '97.0.4692.71-0.1~deb11u1'},
    {'release': '11.0', 'prefix': 'chromium-shell', 'reference': '97.0.4692.71-0.1~deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium / chromium-common / chromium-driver / chromium-l10n / etc');
}
