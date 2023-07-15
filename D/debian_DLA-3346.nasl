#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3346. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171932);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/27");

  script_cve_id("CVE-2023-23934", "CVE-2023-25577");

  script_name(english:"Debian DLA-3346-1 : python-werkzeug - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3346 advisory.

  - Werkzeug is a comprehensive WSGI web application library. Browsers may allow nameless cookies that look
    like `=value` instead of `key=value`. A vulnerable browser may allow a compromised application on an
    adjacent subdomain to exploit this to set a cookie like `=__Host-test=bad` for another subdomain. Werkzeug
    prior to 2.2.3 will parse the cookie `=__Host-test=bad` as __Host-test=bad`. If a Werkzeug application is
    running next to a vulnerable or malicious subdomain which sets such a cookie using a vulnerable browser,
    the Werkzeug application will see the bad cookie value but the valid cookie key. The issue is fixed in
    Werkzeug 2.2.3. (CVE-2023-23934)

  - Werkzeug is a comprehensive WSGI web application library. Prior to version 2.2.3, Werkzeug's multipart
    form data parser will parse an unlimited number of parts, including file parts. Parts can be a small
    amount of bytes, but each requires CPU time to parse and may use more memory as Python data. If a request
    can be made to an endpoint that accesses `request.data`, `request.form`, `request.files`, or
    `request.get_data(parse_form_data=False)`, it can cause unexpectedly high resource usage. This allows an
    attacker to cause a denial of service by sending crafted multipart data to an endpoint that will parse it.
    The amount of CPU time required can block worker processes from handling legitimate requests. The amount
    of RAM required can trigger an out of memory kill of the process. Unlimited file parts can use up memory
    and file handles. If many concurrent requests are sent continuously, this can exhaust or kill all
    available workers. Version 2.2.3 contains a patch for this issue. (CVE-2023-25577)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1031370");
  # https://security-tracker.debian.org/tracker/source-package/python-werkzeug
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98ea39fc");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3346");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-25577");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/python-werkzeug");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python-werkzeug packages.

For Debian 10 buster, these problems have been fixed in version 0.14.1+dfsg1-4+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-werkzeug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-werkzeug-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-werkzeug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'python-werkzeug', 'reference': '0.14.1+dfsg1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'python-werkzeug-doc', 'reference': '0.14.1+dfsg1-4+deb10u2'},
    {'release': '10.0', 'prefix': 'python3-werkzeug', 'reference': '0.14.1+dfsg1-4+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-werkzeug / python-werkzeug-doc / python3-werkzeug');
}
