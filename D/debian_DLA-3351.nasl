#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3351. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172449);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id(
    "CVE-2006-20001",
    "CVE-2021-33193",
    "CVE-2022-36760",
    "CVE-2022-37436"
  );
  script_xref(name:"IAVA", value:"2023-A-0047-S");
  script_xref(name:"IAVA", value:"2021-A-0440-S");

  script_name(english:"Debian DLA-3351-1 : apache2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3351 advisory.

  - A carefully crafted If: request header can cause a memory read, or write of a single zero byte, in a pool
    (heap) memory location beyond the header value sent. This could cause the process to crash. This issue
    affects Apache HTTP Server 2.4.54 and earlier. (CVE-2006-20001)

  - A crafted method sent through HTTP/2 will bypass validation and be forwarded by mod_proxy, which can lead
    to request splitting or cache poisoning. This issue affects Apache HTTP Server 2.4.17 to 2.4.48.
    (CVE-2021-33193)

  - Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of
    Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This
    issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.54 and prior versions.
    (CVE-2022-36760)

  - Prior to Apache HTTP Server 2.4.55, a malicious backend can cause the response headers to be truncated
    early, resulting in some headers being incorporated into the response body. If the later headers have any
    security purpose, they will not be interpreted by the client. (CVE-2022-37436)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/apache2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3351");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2006-20001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33193");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37436");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/apache2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the apache2 packages.

For Debian 10 buster, these problems have been fixed in version 2.4.38-3+deb10u9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33193");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-36760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-proxy-uwsgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'apache2', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'apache2-bin', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'apache2-data', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'apache2-dev', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'apache2-doc', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'apache2-utils', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'libapache2-mod-md', 'reference': '2.4.38-3+deb10u9'},
    {'release': '10.0', 'prefix': 'libapache2-mod-proxy-uwsgi', 'reference': '2.4.38-3+deb10u9'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / apache2-doc / etc');
}
