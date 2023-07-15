#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176855);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/12");

  script_cve_id(
    "CVE-2022-32221",
    "CVE-2022-35252",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-23916"
  );
  script_xref(name:"IAVA", value:"2022-A-0451-S");
  script_xref(name:"IAVA", value:"2023-A-0008-S");
  script_xref(name:"IAVA", value:"2023-A-0108-S");
  script_xref(name:"IAVA", value:"2022-A-0350-S");

  script_name(english:"EulerOS Virtualization 2.11.1 : curl (EulerOS-SA-2023-2066)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to
    ask for data to send, even when the `CURLOPT_POSTFIELDS` option has been set, if the same handle
    previously was used to issue a `PUT` request which used that callback. This flaw may surprise the
    application and cause it to misbehave and either send off the wrong data or use memory after free or
    similar in the subsequent `POST` request. The problem exists in the logic for a reused handle when it is
    changed from a PUT to a POST. (CVE-2022-32221)

  - When curl is used to retrieve and parse cookies from a HTTP(S) server, itaccepts cookies using control
    codes that when later are sent back to a HTTPserver might make the server return 400 responses.
    Effectively allowing a'sister site' to deny service to all siblings. (CVE-2022-35252)

  - curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a non-
    HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to the proxy, and
    then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP proxies often
    only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead return a non-200
    status code to the client. Due to flaws in the error/cleanup handling, this could trigger a double free in
    curl if one of the following schemes were used in the URL for the transfer: dict, gopher, gophers, ldap,
    ldaps, rtmp, rtmps, or telnet. The earliest affected version is 7.77.0. (CVE-2022-42915)

  - In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS
    support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step)
    even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the given URL
    uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, e.g., using
    the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of U+002E (.).
    The earliest affected version is 7.77.0 2021-05-26. (CVE-2022-42916)

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality fail when multiple URLs are requested serially. Using its HSTS support, curl can be
    instructed to use HTTPS instead of usingan insecure clear-text HTTP step even when HTTP is provided in the
    URL. ThisHSTS mechanism would however surprisingly be ignored by subsequent transferswhen done on the same
    command line because the state would not be properlycarried on. (CVE-2023-23914)

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality to behave incorrectly when multiple URLs are requested in parallel. Using its HSTS
    support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP step even when
    HTTP is provided in the URL. This HSTS mechanism would however surprisingly fail when multiple transfers
    are done in parallel as the HSTS cache file gets overwritten by the most recentlycompleted transfer. A
    later HTTP-only transfer to the earlier host name would then *not* get upgraded properly to HSTS.
    (CVE-2023-23915)

  - An allocation of resources without limits or throttling vulnerability exists in curl <v7.88.0 based on the
    'chained' HTTP compression algorithms, meaning that a server response can be compressed multiple times and
    potentially with differentalgorithms. The number of acceptable 'links' in this 'decompression chain'
    wascapped, but the cap was implemented on a per-header basis allowing a maliciousserver to insert a
    virtually unlimited number of compression steps simply byusing many headers. The use of such a
    decompression chain could result in a 'malloc bomb', making curl end up spending enormous amounts of
    allocated heap memory, or trying to and returning out of memory errors. (CVE-2023-23916)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2066
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d403d066");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42915");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.11.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.11.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.11.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "curl-7.79.1-2.h12.eulerosv2r11",
  "libcurl-7.79.1-2.h12.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
