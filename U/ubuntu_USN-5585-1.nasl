#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5585-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164506);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2018-19351",
    "CVE-2018-21030",
    "CVE-2019-9644",
    "CVE-2019-10255",
    "CVE-2019-10856",
    "CVE-2020-26215",
    "CVE-2022-24758",
    "CVE-2022-29238"
  );
  script_xref(name:"USN", value:"5585-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Jupyter Notebook vulnerabilities (USN-5585-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5585-1 advisory.

  - Jupyter Notebook before 5.7.1 allows XSS via an untrusted notebook because nbconvert responses are
    considered to have the same origin as the notebook server. In other words, nbconvert endpoints can execute
    JavaScript with access to the server API. In notebook/nbconvert/handlers.py, NbconvertFileHandler and
    NbconvertPostHandler do not set a Content Security Policy to prevent this. (CVE-2018-19351)

  - Jupyter Notebook before 5.5.0 does not use a CSP header to treat served files as belonging to a separate
    origin. Thus, for example, an XSS payload can be placed in an SVG document. (CVE-2018-21030)

  - An XSSI (cross-site inclusion) vulnerability in Jupyter Notebook before 5.7.6 allows inclusion of
    resources on malicious pages when visited by users who are authenticated with a Jupyter server. Access to
    the content of resources has been demonstrated with Internet Explorer through capturing of error messages,
    though not reproduced with other browsers. This occurs because Internet Explorer's error messages can
    include the content of any invalid JavaScript that was encountered. (CVE-2019-9644)

  - An Open Redirect vulnerability for all browsers in Jupyter Notebook before 5.7.7 and some browsers
    (Chrome, Firefox) in JupyterHub before 0.9.5 allows crafted links to the login page, which will redirect
    to a malicious site after successful login. Servers running on a base_url prefix are not affected.
    (CVE-2019-10255)

  - In Jupyter Notebook before 5.7.8, an open redirect can occur via an empty netloc. This issue exists
    because of an incomplete fix for CVE-2019-10255. (CVE-2019-10856)

  - Jupyter Notebook before version 6.1.5 has an Open redirect vulnerability. A maliciously crafted link to a
    notebook server could redirect the browser to a different website. All notebook servers are technically
    affected, however, these maliciously crafted links can only be reasonably made for known notebook server
    hosts. A link to your notebook server may appear safe, but ultimately redirect to a spoofed server on the
    public internet. The issue is patched in version 6.1.5. (CVE-2020-26215)

  - The Jupyter notebook is a web-based notebook environment for interactive computing. Prior to version
    6.4.9, unauthorized actors can access sensitive information from server logs. Anytime a 5xx error is
    triggered, the auth cookie and other header values are recorded in Jupyter server logs by default.
    Considering these logs do not require root access, an attacker can monitor these logs, steal sensitive
    auth/cookie information, and gain access to the Jupyter server. Jupyter notebook version 6.4.x contains a
    patch for this issue. There are currently no known workarounds. (CVE-2022-24758)

  - Jupyter Notebook is a web-based notebook environment for interactive computing. Prior to version 6.4.12,
    authenticated requests to the notebook server with `ContentsManager.allow_hidden = False` only prevented
    listing the contents of hidden directories, not accessing individual hidden files or files in hidden
    directories (i.e. hidden files were 'hidden' but not 'inaccessible'). This could lead to notebook
    configurations allowing authenticated access to files that may reasonably be expected to be disallowed.
    Because fully authenticated requests are required, this is of relatively low impact. But if a server's
    root directory contains sensitive files whose only protection from the server is being hidden (e.g.
    `~/.ssh` while serving $HOME), then any authenticated requests could access files if their names are
    guessable. Such contexts also necessarily have full access to the server and therefore execution
    permissions, which also generally grants access to all the same files. So this does not generally result
    in any privilege escalation or increase in information access, only an additional, unintended means by
    which the files could be accessed. Version 6.4.12 contains a patch for this issue. There are currently no
    known workarounds. (CVE-2022-29238)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5585-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected jupyter-notebook, python-notebook and / or python3-notebook packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26215");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24758");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:jupyter-notebook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-notebook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-notebook");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'jupyter-notebook', 'pkgver': '5.2.2-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'python-notebook', 'pkgver': '5.2.2-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'python3-notebook', 'pkgver': '5.2.2-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'jupyter-notebook', 'pkgver': '6.0.3-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'python3-notebook', 'pkgver': '6.0.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'jupyter-notebook', 'pkgver': '6.4.8-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'python3-notebook', 'pkgver': '6.4.8-1ubuntu0.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jupyter-notebook / python-notebook / python3-notebook');
}
