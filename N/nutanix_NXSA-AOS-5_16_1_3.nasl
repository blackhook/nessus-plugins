#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164582);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2018-18074",
    "CVE-2018-20060",
    "CVE-2019-0199",
    "CVE-2019-10072",
    "CVE-2019-11135",
    "CVE-2019-11236",
    "CVE-2019-11324",
    "CVE-2019-11487",
    "CVE-2019-12418",
    "CVE-2019-17563",
    "CVE-2019-17569",
    "CVE-2019-17666",
    "CVE-2019-19338",
    "CVE-2020-1935",
    "CVE-2020-1938",
    "CVE-2020-9484",
    "CVE-2020-10531",
    "CVE-2020-11996",
    "CVE-2020-13934",
    "CVE-2020-13935"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.16.1.3)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.16.1.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.16.1.3 advisory.

  - The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon
    receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover
    credentials by sniffing the network. (CVE-2018-18074)

  - urllib3 before version 1.23 does not remove the Authorization HTTP header when following a cross-origin
    redirect (i.e., a redirect that differs in host, port, or scheme). This can allow for credentials in the
    Authorization header to be exposed to unintended hosts or transmitted in cleartext. (CVE-2018-20060)

  - The HTTP/2 implementation in Apache Tomcat 9.0.0.M1 to 9.0.14 and 8.5.0 to 8.5.37 accepted streams with
    excessive numbers of SETTINGS frames and also permitted clients to keep streams open without
    reading/writing request/response data. By keeping streams open for requests that utilised the Servlet
    API's blocking I/O, clients were able to cause server-side threads to block eventually leading to thread
    exhaustion and a DoS. (CVE-2019-0199)

  - The fix for CVE-2019-0199 was incomplete and did not address HTTP/2 connection window exhaustion on write
    in Apache Tomcat versions 9.0.0.M1 to 9.0.19 and 8.5.0 to 8.5.40 . By not sending WINDOW_UPDATE messages
    for the connection window (stream 0) clients were able to cause server-side threads to block eventually
    leading to thread exhaustion and a DoS. (CVE-2019-10072)

  - TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated
    user to potentially enable information disclosure via a side channel with local access. (CVE-2019-11135)

  - In the urllib3 library through 1.24.1 for Python, CRLF injection is possible if the attacker controls the
    request parameter. (CVE-2019-11236)

  - The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA
    certificates is different from the OS store of CA certificates, which results in SSL connections
    succeeding in situations where a verification failure is the correct outcome. This is related to use of
    the ssl_context, ca_certs, or ca_certs_dir argument. (CVE-2019-11324)

  - The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-
    free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - When Apache Tomcat 9.0.0.M1 to 9.0.28, 8.5.0 to 8.5.47, 7.0.0 and 7.0.97 is configured with the JMX Remote
    Lifecycle Listener, a local attacker without access to the Tomcat process or configuration files is able
    to manipulate the RMI registry to perform a man-in-the-middle attack to capture user names and passwords
    used to access the JMX interface. The attacker can then use these credentials to access the JMX interface
    and gain complete control over the Tomcat instance. (CVE-2019-12418)

  - When using FORM authentication with Apache Tomcat 9.0.0.M1 to 9.0.29, 8.5.0 to 8.5.49 and 7.0.0 to 7.0.98
    there was a narrow window where an attacker could perform a session fixation attack. The window was
    considered too narrow for an exploit to be practical but, erring on the side of caution, this issue has
    been treated as a security vulnerability. (CVE-2019-17563)

  - The refactoring present in Apache Tomcat 9.0.28 to 9.0.30, 8.5.48 to 8.5.50 and 7.0.98 to 7.0.99
    introduced a regression. The result of the regression was that invalid Transfer-Encoding headers were
    incorrectly processed leading to a possibility of HTTP Request Smuggling if Tomcat was located behind a
    reverse proxy that incorrectly handled the invalid Transfer-Encoding header in a particular manner. Such a
    reverse proxy is considered unlikely. (CVE-2019-17569)

  - rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel through 5.3.6 lacks a
    certain upper-bound check, leading to a buffer overflow. (CVE-2019-17666)

  - A flaw was found in the fix for CVE-2019-11135, in the Linux upstream kernel versions before 5.5 where,
    the way Intel CPUs handle speculative execution of instructions when a TSX Asynchronous Abort (TAA) error
    occurs. When a guest is running on a host CPU affected by the TAA flaw (TAA_NO=0), but is not affected by
    the MDS issue (MDS_NO=1), the guest was to clear the affected buffers by using a VERW instruction
    mechanism. But when the MDS_NO=1 bit was exported to the guests, the guests did not use the VERW mechanism
    to clear the affected buffers. This issue affects guests running on Cascade Lake CPUs and requires that
    host has 'TSX' enabled. Confidentiality of data is the highest threat associated with this vulnerability.
    (CVE-2019-19338)

  - An issue was discovered in International Components for Unicode (ICU) for C/C++ through 66.1. An integer
    overflow, leading to a heap-based buffer overflow, exists in the UnicodeString::doAppend() function in
    common/unistr.cpp. (CVE-2020-10531)

  - A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to
    9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage for several seconds. If a sufficient number of
    such requests were made on concurrent HTTP/2 connections, the server could become unresponsive.
    (CVE-2020-11996)

  - An h2c direct connection to Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M5 to 9.0.36 and 8.5.1 to 8.5.56
    did not release the HTTP/1.1 processor after the upgrade to HTTP/2. If a sufficient number of such
    requests were made, an OutOfMemoryException could occur leading to a denial of service. (CVE-2020-13934)

  - The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to
    10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to 7.0.104. Invalid payload lengths could
    trigger an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of
    service. (CVE-2020-13935)

  - In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99 the HTTP header parsing code used
    an approach to end-of-line parsing that allowed some invalid HTTP headers to be parsed as valid. This led
    to a possibility of HTTP Request Smuggling if Tomcat was located behind a reverse proxy that incorrectly
    handled the invalid Transfer-Encoding header in a particular manner. Such a reverse proxy is considered
    unlikely. (CVE-2020-1935)

  - When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to
    Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP
    connection. If such connections are available to an attacker, they can be exploited in ways that may be
    surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped
    with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected
    (and recommended in the security guide) that this Connector would be disabled if not required. This
    vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the
    web application - processing any file in the web application as a JSP Further, if the web application
    allowed file upload and stored those files within the web application (or the attacker was able to control
    the content of the web application by some other means) then this, along with the ability to process a
    file as a JSP, made remote code execution possible. It is important to note that mitigation is only
    required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth
    approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to
    Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP
    Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading
    to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
    (CVE-2020-1938)

  - When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to
    7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the
    server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is
    configured with sessionAttributeValueClassNameFilter=null (the default unless a SecurityManager is used)
    or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker
    knows the relative file path from the storage location used by FileStore to the file the attacker has
    control over; then, using a specifically crafted request, the attacker will be able to trigger remote code
    execution via deserialization of the file under their control. Note that all of conditions a) to d) must
    be true for the attack to succeed. (CVE-2020-9484)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.16.1.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb7d890c");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.16.1.3', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.16.1.3 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.16.1.3', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.16.1.3 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
