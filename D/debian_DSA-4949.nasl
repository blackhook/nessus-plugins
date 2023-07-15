#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4949. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152224);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-10241",
    "CVE-2019-10247",
    "CVE-2020-27216",
    "CVE-2020-27223",
    "CVE-2020-28165",
    "CVE-2020-28169",
    "CVE-2021-34428"
  );
  script_xref(name:"IAVA", value:"2020-A-0019");
  script_xref(name:"IAVA", value:"2019-A-0384");
  script_xref(name:"IAVA", value:"2021-A-0035-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DSA-4949-1 : jetty9 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4949 advisory.

  - In Eclipse Jetty version 9.2.26 and older, 9.3.25 and older, and 9.4.15 and older, the server is
    vulnerable to XSS conditions if a remote client USES a specially formatted URL against the DefaultServlet
    or ResourceHandler that is configured for showing a Listing of directory contents. (CVE-2019-10241)

  - In Eclipse Jetty version 7.x, 8.x, 9.2.27 and older, 9.3.26 and older, and 9.4.16 and older, the server
    running on any OS and Jetty version combination will reveal the configured fully qualified directory base
    resource location on the output of the 404 error for not finding a Context that matches the requested
    path. The default server behavior on jetty-distribution and jetty-home will include at the end of the
    Handler tree a DefaultHandler, which is responsible for reporting this 404 error, it presents the various
    configured contexts as HTML for users to click through to. This produced HTML includes output that
    contains the configured fully qualified directory base resource location for each context.
    (CVE-2019-10247)

  - In Eclipse Jetty versions 1.0 thru 9.4.32.v20200930, 10.0.0.alpha1 thru 10.0.0.beta2, and 11.0.0.alpha1
    thru 11.0.0.beta2O, on Unix like systems, the system's temporary directory is shared between all users on
    that system. A collocated user can observe the process of creating a temporary sub directory in the shared
    temporary directory and race to complete the creation of the temporary subdirectory. If the attacker wins
    the race then they will have read and write permission to the subdirectory used to unpack web
    applications, including their WEB-INF/lib jar files and JSP files. If any code is ever executed out of
    this temporary directory, this can lead to a local privilege escalation vulnerability. (CVE-2020-27216)

  - In Eclipse Jetty 9.4.6.v20170531 to 9.4.36.v20210114 (inclusive), 10.0.0, and 11.0.0 when Jetty handles a
    request containing multiple Accept headers with a large number of quality (i.e. q) parameters, the
    server may enter a denial of service (DoS) state due to high CPU usage processing those quality values,
    resulting in minutes of CPU time exhausted processing those quality values. (CVE-2020-27223)

  - The td-agent-builder plugin before 2020-12-18 for Fluentd allows attackers to gain privileges because the
    bin directory is writable by a user account, but a file in bin is executed as NT AUTHORITY\SYSTEM.
    (CVE-2020-28169)

  - For Eclipse Jetty versions <= 9.4.40, <= 10.0.2, <= 11.0.2, if an exception is thrown from the
    SessionListener#sessionDestroyed() method, then the session ID is not invalidated in the session ID
    manager. On deployments with clustered sessions and multiple contexts this can result in a session not
    being invalidated. This can result in an application used on a shared computer being left logged in.
    (CVE-2021-34428)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/jetty9");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4949");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-10241");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-10247");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27216");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27223");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28165");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28169");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-34428");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/jetty9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the jetty9 packages.

For the stable distribution (buster), these problems have been fixed in version 9.4.16-0+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28165");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jetty9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjetty9-extra-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjetty9-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '10.0', 'prefix': 'jetty9', 'reference': '9.4.16-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libjetty9-extra-java', 'reference': '9.4.16-0+deb10u1'},
    {'release': '10.0', 'prefix': 'libjetty9-java', 'reference': '9.4.16-0+deb10u1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jetty9 / libjetty9-extra-java / libjetty9-java');
}
