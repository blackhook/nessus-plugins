#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-25.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164112);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/01");

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
    "CVE-2021-30551",
    "CVE-2022-0789",
    "CVE-2022-0790",
    "CVE-2022-0791",
    "CVE-2022-0792",
    "CVE-2022-0793",
    "CVE-2022-0794",
    "CVE-2022-0795",
    "CVE-2022-0796",
    "CVE-2022-0797",
    "CVE-2022-0798",
    "CVE-2022-0799",
    "CVE-2022-0800",
    "CVE-2022-0801",
    "CVE-2022-0802",
    "CVE-2022-0803",
    "CVE-2022-0804",
    "CVE-2022-0805",
    "CVE-2022-0806",
    "CVE-2022-0807",
    "CVE-2022-0808",
    "CVE-2022-0809",
    "CVE-2022-0971",
    "CVE-2022-0972",
    "CVE-2022-0973",
    "CVE-2022-0974",
    "CVE-2022-0975",
    "CVE-2022-0976",
    "CVE-2022-0977",
    "CVE-2022-0978",
    "CVE-2022-0979",
    "CVE-2022-0980",
    "CVE-2022-1096",
    "CVE-2022-1125",
    "CVE-2022-1127",
    "CVE-2022-1128",
    "CVE-2022-1129",
    "CVE-2022-1130",
    "CVE-2022-1131",
    "CVE-2022-1132",
    "CVE-2022-1133",
    "CVE-2022-1134",
    "CVE-2022-1135",
    "CVE-2022-1136",
    "CVE-2022-1137",
    "CVE-2022-1138",
    "CVE-2022-1139",
    "CVE-2022-1141",
    "CVE-2022-1142",
    "CVE-2022-1143",
    "CVE-2022-1144",
    "CVE-2022-1145",
    "CVE-2022-1146",
    "CVE-2022-1232",
    "CVE-2022-1305",
    "CVE-2022-1306",
    "CVE-2022-1307",
    "CVE-2022-1308",
    "CVE-2022-1309",
    "CVE-2022-1310",
    "CVE-2022-1311",
    "CVE-2022-1312",
    "CVE-2022-1313",
    "CVE-2022-1314",
    "CVE-2022-1364",
    "CVE-2022-1477",
    "CVE-2022-1478",
    "CVE-2022-1479",
    "CVE-2022-1481",
    "CVE-2022-1482",
    "CVE-2022-1483",
    "CVE-2022-1484",
    "CVE-2022-1485",
    "CVE-2022-1486",
    "CVE-2022-1487",
    "CVE-2022-1488",
    "CVE-2022-1489",
    "CVE-2022-1490",
    "CVE-2022-1491",
    "CVE-2022-1492",
    "CVE-2022-1493",
    "CVE-2022-1494",
    "CVE-2022-1495",
    "CVE-2022-1496",
    "CVE-2022-1497",
    "CVE-2022-1498",
    "CVE-2022-1499",
    "CVE-2022-1500",
    "CVE-2022-1501",
    "CVE-2022-1633",
    "CVE-2022-1634",
    "CVE-2022-1635",
    "CVE-2022-1636",
    "CVE-2022-1637",
    "CVE-2022-1639",
    "CVE-2022-1640",
    "CVE-2022-1641",
    "CVE-2022-1853",
    "CVE-2022-1854",
    "CVE-2022-1855",
    "CVE-2022-1856",
    "CVE-2022-1857",
    "CVE-2022-1858",
    "CVE-2022-1859",
    "CVE-2022-1860",
    "CVE-2022-1861",
    "CVE-2022-1862",
    "CVE-2022-1863",
    "CVE-2022-1864",
    "CVE-2022-1865",
    "CVE-2022-1866",
    "CVE-2022-1867",
    "CVE-2022-1868",
    "CVE-2022-1869",
    "CVE-2022-1870",
    "CVE-2022-1871",
    "CVE-2022-1872",
    "CVE-2022-1873",
    "CVE-2022-1874",
    "CVE-2022-1875",
    "CVE-2022-1876",
    "CVE-2022-2007",
    "CVE-2022-2010",
    "CVE-2022-2011",
    "CVE-2022-2156",
    "CVE-2022-2157",
    "CVE-2022-2158",
    "CVE-2022-2160",
    "CVE-2022-2161",
    "CVE-2022-2162",
    "CVE-2022-2163",
    "CVE-2022-2164",
    "CVE-2022-2165",
    "CVE-2022-22021",
    "CVE-2022-24475",
    "CVE-2022-24523",
    "CVE-2022-26891",
    "CVE-2022-26894",
    "CVE-2022-26895",
    "CVE-2022-26900",
    "CVE-2022-26905",
    "CVE-2022-26908",
    "CVE-2022-26909",
    "CVE-2022-26912",
    "CVE-2022-29144",
    "CVE-2022-29146",
    "CVE-2022-29147",
    "CVE-2022-30127",
    "CVE-2022-30128",
    "CVE-2022-30192",
    "CVE-2022-33638",
    "CVE-2022-33639"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/06");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"GLSA-202208-25 : Chromium, Google Chrome, Microsoft Edge, QtWebEngine: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-25 (Chromium, Google Chrome, Microsoft Edge,
QtWebEngine: Multiple Vulnerabilities)

  - Type confusion in V8 in Google Chrome prior to 91.0.4472.101 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30551)

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

  - Heap buffer overflow in ANGLE in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0789)

  - Use after free in Cast UI in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a
    user to engage in specific user interaction to potentially perform a sandbox escape via a crafted HTML
    page. (CVE-2022-0790)

  - Use after free in Omnibox in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a
    user to engage in specific user interactions to potentially exploit heap corruption via user interactions.
    (CVE-2022-0791)

  - Out of bounds read in ANGLE in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0792)

  - Use after free in Cast in Google Chrome prior to 99.0.4844.51 allowed an attacker who convinced a user to
    install a malicious extension and engage in specific user interaction to potentially exploit heap
    corruption via a crafted Chrome Extension. (CVE-2022-0793)

  - Use after free in WebShare in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced
    a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML
    page. (CVE-2022-0794)

  - Type confusion in Blink Layout in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0795)

  - Use after free in Media in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-0796)

  - Out of bounds memory access in Mojo in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    perform an out of bounds memory write via a crafted HTML page. (CVE-2022-0797)

  - Use after free in MediaStream in Google Chrome prior to 99.0.4844.51 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension. (CVE-2022-0798)

  - Insufficient policy enforcement in Installer in Google Chrome on Windows prior to 99.0.4844.51 allowed a
    remote attacker to perform local privilege escalation via a crafted offline installer file.
    (CVE-2022-0799)

  - Heap buffer overflow in Cast UI in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-0800)

  - Inappropriate implementation in Full screen mode in Google Chrome on Android prior to 99.0.4844.51 allowed
    a remote attacker to hide the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-0802,
    CVE-2022-0804)

  - Inappropriate implementation in Permissions in Google Chrome prior to 99.0.4844.51 allowed a remote
    attacker to tamper with the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-0803)

  - Use after free in Browser Switcher in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via user
    interaction. (CVE-2022-0805)

  - Data leak in Canvas in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a user
    to engage in screen sharing to potentially leak cross-origin data via a crafted HTML page. (CVE-2022-0806)

  - Inappropriate implementation in Autofill in Google Chrome prior to 99.0.4844.51 allowed a remote attacker
    to bypass navigation restrictions via a crafted HTML page. (CVE-2022-0807)

  - Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 99.0.4844.51 allowed a remote
    attacker who convinced a user to engage in a series of user interaction to potentially exploit heap
    corruption via user interactions. (CVE-2022-0808)

  - Out of bounds memory access in WebXR in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0809)

  - Use after free in Blink Layout in Google Chrome on Android prior to 99.0.4844.74 allowed a remote attacker
    who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-0971)

  - Use after free in Extensions in Google Chrome prior to 99.0.4844.74 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-0972)

  - Use after free in Safe Browsing in Google Chrome prior to 99.0.4844.74 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0973)

  - Use after free in Splitscreen in Google Chrome on Chrome OS prior to 99.0.4844.74 allowed a remote
    attacker who convinced a user to engage in specific user interaction to potentially exploit heap
    corruption via a crafted HTML page. (CVE-2022-0974)

  - Use after free in ANGLE in Google Chrome prior to 99.0.4844.74 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-0975, CVE-2022-0978)

  - Heap buffer overflow in GPU in Google Chrome prior to 99.0.4844.74 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0976)

  - Use after free in Browser UI in Google Chrome on Chrome OS prior to 99.0.4844.74 allowed a remote attacker
    who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-0977)

  - Use after free in Safe Browsing in Google Chrome on Android prior to 99.0.4844.74 allowed a remote
    attacker who convinced a user to engage in specific user interaction to potentially exploit heap
    corruption via a crafted HTML page. (CVE-2022-0979)

  - Use after free in New Tab Page in Google Chrome prior to 99.0.4844.74 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific user
    interactions. (CVE-2022-0980)

  - Type confusion in V8 in Google Chrome prior to 99.0.4844.84 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1096)

  - Use after free in Portals in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced
    a user to engage in specific user interaction to potentially exploit heap corruption via user interaction.
    (CVE-2022-1125)

  - Use after free in QR Code Generator in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via user
    interaction. (CVE-2022-1127)

  - Inappropriate implementation in Web Share API in Google Chrome on Windows prior to 100.0.4896.60 allowed
    an attacker on the local network segment to leak cross-origin data via a crafted HTML page.
    (CVE-2022-1128)

  - Inappropriate implementation in Full Screen Mode in Google Chrome on Android prior to 100.0.4896.60
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2022-1129)

  - Insufficient validation of trust input in WebOTP in Google Chrome on Android prior to 100.0.4896.60
    allowed a remote attacker to send arbitrary intents from any app via a malicious app. (CVE-2022-1130)

  - Use after free in Cast UI in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1131)

  - Inappropriate implementation in Virtual Keyboard in Google Chrome on Chrome OS prior to 100.0.4896.60
    allowed a local attacker to bypass navigation restrictions via physical access to the device.
    (CVE-2022-1132)

  - Use after free in WebRTC Perf in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1133)

  - Type confusion in V8 in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1134)

  - Use after free in Shopping Cart in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to
    potentially exploit heap corruption via standard feature user interaction. (CVE-2022-1135)

  - Use after free in Tab Strip in Google Chrome prior to 100.0.4896.60 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific set of user
    gestures. (CVE-2022-1136)

  - Inappropriate implementation in Extensions in Google Chrome prior to 100.0.4896.60 allowed an attacker who
    convinced a user to install a malicious extension to leak potentially sensitive information via a crafted
    HTML page. (CVE-2022-1137)

  - Inappropriate implementation in Web Cursor in Google Chrome prior to 100.0.4896.60 allowed a remote
    attacker who had compromised the renderer process to obscure the contents of the Omnibox (URL bar) via a
    crafted HTML page. (CVE-2022-1138)

  - Inappropriate implementation in Background Fetch API in Google Chrome prior to 100.0.4896.60 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-1139)

  - Use after free in File Manager in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via
    specific user gesture. (CVE-2022-1141)

  - Heap buffer overflow in WebUI in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via
    specific input into DevTools. (CVE-2022-1142, CVE-2022-1143)

  - Use after free in WebUI in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a
    user to engage in specific user interaction to potentially exploit heap corruption via specific input into
    DevTools. (CVE-2022-1144)

  - Use after free in Extensions in Google Chrome prior to 100.0.4896.60 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific user interaction
    and profile destruction. (CVE-2022-1145)

  - Inappropriate implementation in Resource Timing in Google Chrome prior to 100.0.4896.60 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-1146)

  - Type confusion in V8 in Google Chrome prior to 100.0.4896.75 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1232)

  - Use after free in storage in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1305)

  - Inappropriate implementation in compositing in Google Chrome prior to 100.0.4896.88 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-1306)

  - Inappropriate implementation in full screen in Google Chrome on Android prior to 100.0.4896.88 allowed a
    remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-1307)

  - Use after free in BFCache in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1308)

  - Insufficient policy enforcement in developer tools in Google Chrome prior to 100.0.4896.88 allowed a
    remote attacker to potentially perform a sandbox escape via a crafted HTML page. (CVE-2022-1309)

  - Use after free in regular expressions in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1310)

  - Use after free in shell in Google Chrome on ChromeOS prior to 100.0.4896.88 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1311)

  - Use after free in storage in Google Chrome prior to 100.0.4896.88 allowed an attacker who convinced a user
    to install a malicious extension to potentially perform a sandbox escape via a crafted Chrome Extension.
    (CVE-2022-1312)

  - Use after free in tab groups in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1313)

  - Type confusion in V8 in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1314)

  - Type confusion in V8 Turbofan in Google Chrome prior to 100.0.4896.127 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1364)

  - Use after free in Vulkan in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1477)

  - Use after free in SwiftShader in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1478)

  - Use after free in ANGLE in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1479)

  - Use after free in Sharing in Google Chrome on Mac prior to 101.0.4951.41 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-1481)

  - Inappropriate implementation in WebGL in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1482)

  - Heap buffer overflow in WebGPU in Google Chrome prior to 101.0.4951.41 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-1483)

  - Heap buffer overflow in Web UI Settings in Google Chrome prior to 101.0.4951.41 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1484)

  - Use after free in File System API in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1485)

  - Type confusion in V8 in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (CVE-2022-1486)

  - Use after free in Ozone in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via running a Wayland test. (CVE-2022-1487)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 101.0.4951.41 allowed an attacker
    who convinced a user to install a malicious extension to leak cross-origin data via a crafted Chrome
    Extension. (CVE-2022-1488)

  - Out of bounds memory access in UI Shelf in Google Chrome on Chrome OS, Lacros prior to 101.0.4951.41
    allowed a remote attacker to potentially exploit heap corruption via specific user interactions.
    (CVE-2022-1489)

  - Use after free in Browser Switcher in Google Chrome prior to 101.0.4951.41 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-1490)

  - Use after free in Bookmarks in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via specific and direct user interaction. (CVE-2022-1491)

  - Insufficient data validation in Blink Editing in Google Chrome prior to 101.0.4951.41 allowed a remote
    attacker to inject arbitrary scripts or HTML via a crafted HTML page. (CVE-2022-1492)

  - Use after free in Dev Tools in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via specific and direct user interaction. (CVE-2022-1493)

  - Insufficient data validation in Trusted Types in Google Chrome prior to 101.0.4951.41 allowed a remote
    attacker to bypass trusted types policy via a crafted HTML page. (CVE-2022-1494)

  - Incorrect security UI in Downloads in Google Chrome on Android prior to 101.0.4951.41 allowed a remote
    attacker to spoof the APK downloads dialog via a crafted HTML page. (CVE-2022-1495)

  - Use after free in File Manager in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via specific and direct user interaction. (CVE-2022-1496)

  - Inappropriate implementation in Input in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    spoof the contents of cross-origin websites via a crafted HTML page. (CVE-2022-1497)

  - Inappropriate implementation in HTML Parser in Google Chrome prior to 101.0.4951.41 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-1498)

  - Inappropriate implementation in WebAuthentication in Google Chrome prior to 101.0.4951.41 allowed a remote
    attacker to bypass same origin policy via a crafted HTML page. (CVE-2022-1499)

  - Insufficient data validation in Dev Tools in Google Chrome prior to 101.0.4951.41 allowed a remote
    attacker to bypass content security policy via a crafted HTML page. (CVE-2022-1500)

  - Inappropriate implementation in iframe in Google Chrome prior to 101.0.4951.41 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (CVE-2022-1501)

  - Use after free in Sharesheet in Google Chrome on Chrome OS prior to 101.0.4951.64 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via specific user interactions. (CVE-2022-1633)

  - Use after free in Browser UI in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who had
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    user interactions. (CVE-2022-1634)

  - Use after free in Permission Prompts in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific
    user interactions. (CVE-2022-1635)

  - Use after free in Performance APIs in Google Chrome prior to 101.0.4951.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1636)

  - Inappropriate implementation in Web Contents in Google Chrome prior to 101.0.4951.64 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-1637)

  - Use after free in ANGLE in Google Chrome prior to 101.0.4951.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1639)

  - Use after free in Sharing in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who convinced
    a user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML
    page. (CVE-2022-1640)

  - Use after free in Web UI Diagnostics in Google Chrome on Chrome OS prior to 101.0.4951.64 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via specific user interaction. (CVE-2022-1641)

  - Use after free in Indexed DB in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2022-1853)

  - Use after free in ANGLE in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1854)

  - Use after free in Messaging in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1855)

  - Use after free in User Education in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension or specific user interaction. (CVE-2022-1856)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 102.0.5005.61 allowed a
    remote attacker to bypass file system restrictions via a crafted HTML page. (CVE-2022-1857)

  - Out of bounds read in DevTools in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to
    perform an out of bounds memory read via specific user interaction. (CVE-2022-1858)

  - Use after free in Performance Manager in Google Chrome prior to 102.0.5005.61 allowed a remote attacker
    who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-1859)

  - Use after free in UI Foundations in Google Chrome on Chrome OS prior to 102.0.5005.61 allowed a remote
    attacker who convinced a user to engage in specific user interaction to potentially exploit heap
    corruption via specific user interactions. (CVE-2022-1860)

  - Use after free in Sharing in Google Chrome on Chrome OS prior to 102.0.5005.61 allowed a remote attacker
    who convinced a user to enage in specific user interactions to potentially exploit heap corruption via
    specific user interaction. (CVE-2022-1861)

  - Inappropriate implementation in Extensions in Google Chrome prior to 102.0.5005.61 allowed an attacker who
    convinced a user to install a malicious extension to bypass profile restrictions via a crafted HTML page.
    (CVE-2022-1862)

  - Use after free in Tab Groups in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension and specific user interaction. (CVE-2022-1863)

  - Use after free in WebApp Installs in Google Chrome prior to 102.0.5005.61 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension and specific user interaction. (CVE-2022-1864)

  - Use after free in Bookmarks in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension and specific user interaction. (CVE-2022-1865)

  - Use after free in Tablet Mode in Google Chrome on Chrome OS prior to 102.0.5005.61 allowed a remote
    attacker who convinced a user to engage in specific user interactions to potentially exploit heap
    corruption via specific user interactions. (CVE-2022-1866)

  - Insufficient validation of untrusted input in Data Transfer in Google Chrome prior to 102.0.5005.61
    allowed a remote attacker to bypass same origin policy via a crafted clipboard content. (CVE-2022-1867)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 102.0.5005.61 allowed an attacker
    who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted HTML
    page. (CVE-2022-1868)

  - Type Confusion in V8 in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1869)

  - Use after free in App Service in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension. (CVE-2022-1870)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 102.0.5005.61 allowed an
    attacker who convinced a user to install a malicious extension to bypass file system policy via a crafted
    HTML page. (CVE-2022-1871)

  - Insufficient policy enforcement in Extensions API in Google Chrome prior to 102.0.5005.61 allowed an
    attacker who convinced a user to install a malicious extension to bypass downloads policy via a crafted
    HTML page. (CVE-2022-1872)

  - Insufficient policy enforcement in COOP in Google Chrome prior to 102.0.5005.61 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (CVE-2022-1873)

  - Insufficient policy enforcement in Safe Browsing in Google Chrome on Mac prior to 102.0.5005.61 allowed a
    remote attacker to bypass downloads protection policy via a crafted HTML page. (CVE-2022-1874)

  - Inappropriate implementation in PDF in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (CVE-2022-1875)

  - Heap buffer overflow in DevTools in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-1876)

  - Use after free in WebGPU in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2007)

  - Out of bounds read in compositing in Google Chrome prior to 102.0.5005.115 allowed a remote attacker who
    had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2022-2010)

  - Use after free in ANGLE in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2011)

  - Use after free in Core in Google Chrome prior to 103.0.5060.53 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2156)

  - Use after free in Interest groups in Google Chrome prior to 103.0.5060.53 allowed a remote attacker who
    had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-2157)

  - Type confusion in V8 in Google Chrome prior to 103.0.5060.53 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-2158)

  - Insufficient policy enforcement in DevTools in Google Chrome on Windows prior to 103.0.5060.53 allowed an
    attacker who convinced a user to install a malicious extension to obtain potentially sensitive information
    from a user's local files via a crafted HTML page. (CVE-2022-2160)

  - Use after free in WebApp Provider in Google Chrome prior to 103.0.5060.53 allowed a remote attacker who
    convinced the user to engage in specific user interactions to potentially exploit heap corruption via
    specific UI interactions. (CVE-2022-2161)

  - Insufficient policy enforcement in File System API in Google Chrome on Windows prior to 103.0.5060.53
    allowed a remote attacker to bypass file system access via a crafted HTML page. (CVE-2022-2162)

  - Use after free in Cast UI and Toolbar in Google Chrome prior to 103.0.5060.134 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via UI
    interaction. (CVE-2022-2163)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 103.0.5060.53 allowed an attacker
    who convinced a user to install a malicious extension to bypass discretionary access control via a crafted
    HTML page. (CVE-2022-2164)

  - Insufficient data validation in URL formatting in Google Chrome prior to 103.0.5060.53 allowed a remote
    attacker to perform domain spoofing via IDN homographs via a crafted domain name. (CVE-2022-2165)

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability. (CVE-2022-22021)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-26891, CVE-2022-26894, CVE-2022-26895, CVE-2022-26900, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-24475)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability. (CVE-2022-24523, CVE-2022-26905)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26894, CVE-2022-26895, CVE-2022-26900, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-26891)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26891, CVE-2022-26895, CVE-2022-26900, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-26894)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26891, CVE-2022-26894, CVE-2022-26900, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-26895)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26891, CVE-2022-26894, CVE-2022-26895, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-26900)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26891, CVE-2022-26894, CVE-2022-26895, CVE-2022-26900, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-26908)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26891, CVE-2022-26894, CVE-2022-26895, CVE-2022-26900, CVE-2022-26908,
    CVE-2022-26912. (CVE-2022-26909)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26891, CVE-2022-26894, CVE-2022-26895, CVE-2022-26900, CVE-2022-26908,
    CVE-2022-26909. (CVE-2022-26912)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-30128. (CVE-2022-30127)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-30127. (CVE-2022-30128)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-33638, CVE-2022-33639. (CVE-2022-30192)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-30192, CVE-2022-33639. (CVE-2022-33638)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-30192, CVE-2022-33638. (CVE-2022-33639)

  - This CVE was assigned by Chrome. Microsoft Edge (Chromium-based) ingests Chromium, which addresses this
    vulnerability. Please see Google Chrome Releases for more information. (CVE-2022-0801)
    
  -  Please review the referenced CVE identifiers for details.  (CVE-2022-29144, CVE-2022-29146,
    CVE-2022-29147)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-25");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=773040");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=787950");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=800181");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=810781");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=815397");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=828519");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829161");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834477");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835397");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835761");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836011");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836381");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836777");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836830");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=837497");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=838049");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=838433");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=838682");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=841371");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=843035");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=843728");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=847370");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=847613");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=848864");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=851003");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=851009");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=853229");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=853643");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=854372");
  script_set_attribute(attribute:"solution", value:
"All Chromium users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-103.0.5060.53
        
All Chromium binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-bin-103.0.5060.53
        
All Google Chrome users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/google-chrome-103.0.5060.53
        
All Microsoft Edge users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-103.0.5060.53
        
All QtWebEngine users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-qt/qtwebengine-5.15.5_p20220618");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0809");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1853");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:microsoft-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "dev-qt/qtwebengine",
    'unaffected' : make_list("ge 5.15.5_p20220618"),
    'vulnerable' : make_list("lt 5.15.5_p20220618")
  },
  {
    'name' : "www-client/chromium",
    'unaffected' : make_list("ge 103.0.5060.53"),
    'vulnerable' : make_list("lt 103.0.5060.53")
  },
  {
    'name' : "www-client/google-chrome",
    'unaffected' : make_list("ge 103.0.5060.53"),
    'vulnerable' : make_list("lt 103.0.5060.53")
  },
  {
    'name' : "www-client/microsoft-edge",
    'unaffected' : make_list("ge 101.0.1210.47"),
    'vulnerable' : make_list("lt 101.0.1210.47")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome / Microsoft Edge / QtWebEngine");
}
