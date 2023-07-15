#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(175043);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id(
    "CVE-2015-20107",
    "CVE-2021-3654",
    "CVE-2021-28363",
    "CVE-2021-28861",
    "CVE-2021-29921",
    "CVE-2022-0391",
    "CVE-2022-37454",
    "CVE-2022-42919",
    "CVE-2022-45061"
  );

  script_name(english:"GLSA-202305-02 : Python, PyPy3: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-02 (Python, PyPy3: Multiple Vulnerabilities)

  - In Python (aka CPython) up to 3.10.8, the mailcap module does not add escape characters into commands
    discovered in the system mailcap file. This may allow attackers to inject shell commands into applications
    that call mailcap.findmatch with untrusted input (if they lack validation of user-provided filenames or
    arguments). The fix is also back-ported to 3.7, 3.8, 3.9 (CVE-2015-20107)

  - A vulnerability was found in openstack-nova's console proxy, noVNC. By crafting a malicious URL, noVNC
    could be made to redirect to any desired URL. (CVE-2021-3654)

  - The urllib3 library 1.26.x before 1.26.4 for Python omits SSL certificate validation in some cases
    involving HTTPS to HTTPS proxies. The initial connection to the HTTPS proxy (if an SSLContext isn't given
    via proxy_config) doesn't verify the hostname of the certificate. This means certificates for different
    servers that still validate properly with the default urllib3 SSLContext will be silently accepted.
    (CVE-2021-28363)

  - ** DISPUTED ** Python 3.x through 3.10 has an open redirection vulnerability in lib/http/server.py due to
    no protection against multiple (/) at the beginning of URI path which may leads to information disclosure.
    NOTE: this is disputed by a third party because the http.server.html documentation page states Warning:
    http.server is not recommended for production. It only implements basic security checks. (CVE-2021-28861)

  - In Python before 3,9,5, the ipaddress library mishandles leading zero characters in the octets of an IP
    address string. This (in some situations) allows attackers to bypass access control that is based on IP
    addresses. (CVE-2021-29921)

  - A flaw was found in Python, specifically within the urllib.parse module. This module helps break Uniform
    Resource Locator (URL) strings into components. The issue involves how the urlparse method does not
    sanitize input and allows characters like '\r' and '\n' in the URL path. This flaw allows an attacker to
    input a crafted URL, leading to injection attacks. This flaw affects Python versions prior to 3.10.0b1,
    3.9.5, 3.8.11, 3.7.11 and 3.6.14. (CVE-2022-0391)

  - The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow and resultant buffer
    overflow that allows attackers to execute arbitrary code or eliminate expected cryptographic properties.
    This occurs in the sponge function interface. (CVE-2022-37454)

  - Python 3.9.x before 3.9.16 and 3.10.x before 3.10.9 on Linux allows local privilege escalation in a non-
    default configuration. The Python multiprocessing library, when used with the forkserver start method on
    Linux, allows pickles to be deserialized from any user in the same machine local network namespace, which
    in many system configurations means any user on the same machine. Pickles can execute arbitrary code.
    Thus, this allows for local user privilege escalation to the user that any forkserver process is running
    as. Setting multiprocessing.util.abstract_sockets_supported to False is a workaround. The forkserver start
    method for multiprocessing is not the default start method. This issue is Linux specific because only
    Linux supports abstract namespace sockets. CPython before 3.9 does not make use of Linux abstract
    namespace sockets by default. Support for users manually specifying an abstract namespace socket was added
    as a bugfix in 3.7.8 and 3.8.3, but users would need to make specific uncommon API calls in order to do
    that in CPython before 3.9. (CVE-2022-42919)

  - An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path
    when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
    being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by
    remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger
    excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname.
    For example, the attack payload could be placed in the Location header of an HTTP response with status
    code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16. (CVE-2022-45061)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=787260");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=793833");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=811165");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834533");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835443");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=838250");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=864747");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=876815");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=877851");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878385");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=880629");
  script_set_attribute(attribute:"solution", value:
"All Python 3.8 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.8.15_p3:3.8
        
All Python 3.9 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.9.15_p3:3.9
        
All Python 3.10 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.10.8_p3:3.10
        
All Python 3.11 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.11.0_p2:3.11
        
All Python 3.12 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.12.0_alpha1_p2
        
All PyPy3 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-python/pypy3-7.3.9_p9");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pypy3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.10.8_p3", "lt 3.10.0"),
    'vulnerable' : make_list("lt 3.10.8_p3")
  },
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.11.0_p2", "lt 3.11.0"),
    'vulnerable' : make_list("lt 3.11.0_p2")
  },
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.12.0_alpha1_p2", "lt 3.12.0"),
    'vulnerable' : make_list("lt 3.12.0_alpha1_p2")
  },
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.8.15_p3", "lt 3.8.0"),
    'vulnerable' : make_list("lt 3.8.15_p3")
  },
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.9.15_p3", "lt 3.9.0"),
    'vulnerable' : make_list("lt 3.9.15_p3")
  },
  {
    'name' : 'dev-python/pypy3',
    'unaffected' : make_list("ge 7.3.9_p9"),
    'vulnerable' : make_list("lt 7.3.9_p9")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Python / PyPy3');
}
