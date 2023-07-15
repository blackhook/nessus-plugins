#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175200);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/07");

  script_cve_id(
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23943",
    "CVE-2022-26377",
    "CVE-2022-28614",
    "CVE-2022-28615",
    "CVE-2022-29404",
    "CVE-2022-30522"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.0 : httpd (EulerOS-SA-2023-1737)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - A carefully crafted request body can cause a read to a random memory area which could cause the process to
    crash. This issue affects Apache HTTP Server 2.4.52 and earlier. (CVE-2022-22719)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

  - If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems
    an integer overflow happens which later causes out of bounds writes. This issue affects Apache HTTP Server
    2.4.52 and earlier. (CVE-2022-22721)

  - Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap
    memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and
    prior versions. (CVE-2022-23943)

  - Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of
    Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This
    issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.
    (CVE-2022-26377)

  - The ap_rwrite() function in Apache HTTP Server 2.4.53 and earlier may read unintended memory if an
    attacker can cause the server to reflect very large input using ap_rwrite() or ap_rputs(), such as with
    mod_luas r:puts() function. Modules compiled and distributed separately from Apache HTTP Server that use
    the 'ap_rputs' function and may pass it a very large (INT_MAX or larger) string must be compiled against
    current headers to resolve the issue. (CVE-2022-28614)

  - Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read beyond bounds in
    ap_strcmp_match() when provided with an extremely large input buffer. While no code distributed with the
    server can be coerced into such a call, third-party modules or lua scripts that use ap_strcmp_match() may
    hypothetically be affected. (CVE-2022-28615)

  - In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua script that calls r:parsebody(0)
    may cause a denial of service due to no default limit on possible input size. (CVE-2022-29404)

  - If Apache HTTP Server 2.4.53 is configured to do transformations with mod_sed in contexts where the input
    to mod_sed may be very large, mod_sed may make excessively large memory allocations and trigger an abort.
    (CVE-2022-30522)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1737
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?084417e5");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23943");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "httpd-2.4.6-80.1.h17",
  "httpd-tools-2.4.6-80.1.h17",
  "mod_ssl-2.4.6-80.1.h17"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
