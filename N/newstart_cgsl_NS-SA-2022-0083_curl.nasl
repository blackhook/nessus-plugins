#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0083. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167463);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-8231",
    "CVE-2020-8284",
    "CVE-2020-8285",
    "CVE-2020-8286",
    "CVE-2021-22922",
    "CVE-2021-22923",
    "CVE-2021-22924",
    "CVE-2021-22946",
    "CVE-2021-22947"
  );
  script_xref(name:"IAVA", value:"2020-A-0581");
  script_xref(name:"IAVA", value:"2020-A-0389-S");
  script_xref(name:"IAVA", value:"2021-A-0352-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL MAIN 6.02 : curl Multiple Vulnerabilities (NS-SA-2022-0083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has curl packages installed that are affected by multiple
vulnerabilities:

  - Due to use of a dangling pointer, libcurl 7.29.0 through 7.71.1 can use the wrong connection when sending
    data. (CVE-2020-8231)

  - A malicious server can use the FTP PASV response to trick curl 7.73.0 and earlier into connecting back to
    a given IP address and port, and this way potentially make curl extract information about services that
    are otherwise private and not disclosed, for example doing port scanning and service banner extractions.
    (CVE-2020-8284)

  - curl 7.21.0 to and including 7.73.0 is vulnerable to uncontrolled recursion due to a stack overflow issue
    in FTP wildcard match parsing. (CVE-2020-8285)

  - curl 7.41.0 through 7.73.0 is vulnerable to an improper check for certificate revocation due to
    insufficient verification of the OCSP response. (CVE-2020-8286)

  - When curl is instructed to download content using the metalink feature, thecontents is verified against a
    hash provided in the metalink XML file.The metalink XML file points out to the client how to get the same
    contentfrom a set of different URLs, potentially hosted by different servers and theclient can then
    download the file from one or several of them. In a serial orparallel manner.If one of the servers hosting
    the contents has been breached and the contentsof the specific file on that server is replaced with a
    modified payload, curlshould detect this when the hash of the file mismatches after a completeddownload.
    It should remove the contents and instead try getting the contentsfrom another URL. This is not done, and
    instead such a hash mismatch is onlymentioned in text and the potentially malicious content is kept in the
    file ondisk. (CVE-2021-22922)

  - When curl is instructed to get content using the metalink feature, and a user name and password are used
    to download the metalink XML file, those same credentials are then subsequently passed on to each of the
    servers from which curl will download or try to download the contents from. Often contrary to the user's
    expectations and intentions and without telling the user it happened. (CVE-2021-22923)

  - libcurl keeps previously used connections in a connection pool for subsequenttransfers to reuse, if one of
    them matches the setup.Due to errors in the logic, the config matching function did not take 'issuercert'
    into account and it compared the involved paths *case insensitively*,which could lead to libcurl reusing
    wrong connections.File paths are, or can be, case sensitive on many systems but not all, and caneven vary
    depending on used file systems.The comparison also didn't include the 'issuer cert' which a transfer can
    setto qualify how to verify the server certificate. (CVE-2021-22924)

  - A user can tell curl >= 7.20.0 and <= 7.78.0 to require a successful upgrade to TLS when speaking to an
    IMAP, POP3 or FTP server (`--ssl-reqd` on the command line or`CURLOPT_USE_SSL` set to `CURLUSESSL_CONTROL`
    or `CURLUSESSL_ALL` withlibcurl). This requirement could be bypassed if the server would return a properly
    crafted but perfectly legitimate response.This flaw would then make curl silently continue its operations
    **withoutTLS** contrary to the instructions and expectations, exposing possibly sensitive data in clear
    text over the network. (CVE-2021-22946)

  - When curl >= 7.20.0 and <= 7.78.0 connects to an IMAP or POP3 server to retrieve data using STARTTLS to
    upgrade to TLS security, the server can respond and send back multiple responses at once that curl caches.
    curl would then upgrade to TLS but not flush the in-queue of cached responses but instead continue using
    and trustingthe responses it got *before* the TLS handshake as if they were authenticated.Using this flaw,
    it allows a Man-In-The-Middle attacker to first inject the fake responses, then pass-through the TLS
    traffic from the legitimate server and trick curl into sending data back to the user thinking the
    attacker's injected data comes from the TLS-protected server. (CVE-2021-22947)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0083");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8231");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8284");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8285");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8286");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22922");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22923");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22924");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22946");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22947");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL curl packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'curl-7.61.1-18.el8_4.2',
    'libcurl-7.61.1-18.el8_4.2',
    'libcurl-devel-7.61.1-18.el8_4.2'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl');
}
