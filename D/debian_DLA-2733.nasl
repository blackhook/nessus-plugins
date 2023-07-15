#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2733. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152349);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-30640", "CVE-2021-33037");
  script_xref(name:"IAVA", value:"2021-A-0303-S");

  script_name(english:"Debian DLA-2733-1 : tomcat8 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2733 advisory.

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

  - Apache Tomcat 10.0.0-M1 to 10.0.6, 9.0.0.M1 to 9.0.46 and 8.5.0 to 8.5.66 did not correctly parse the HTTP
    transfer-encoding request header in some circumstances leading to the possibility to request smuggling
    when used with a reverse proxy. Specifically: - Tomcat incorrectly ignored the transfer encoding header if
    the client declared it would only accept an HTTP/1.0 response; - Tomcat honoured the identify encoding;
    and - Tomcat did not ensure that, if present, the chunked encoding was the final encoding.
    (CVE-2021-33037)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=991046");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tomcat8");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33037");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/tomcat8");
  script_set_attribute(attribute:"solution", value:
"Upgrade the tomcat8 packages.

For Debian 9 stretch, these problems have been fixed in version 8.5.54-0+deb9u7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.1-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.1-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat8-embed-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat8-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '9.0', 'prefix': 'libservlet3.1-java', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'libservlet3.1-java-doc', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'libtomcat8-embed-java', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'libtomcat8-java', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'tomcat8', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'tomcat8-admin', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'tomcat8-common', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'tomcat8-docs', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'tomcat8-examples', 'reference': '8.5.54-0+deb9u7'},
    {'release': '9.0', 'prefix': 'tomcat8-user', 'reference': '8.5.54-0+deb9u7'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libservlet3.1-java / libservlet3.1-java-doc / libtomcat8-embed-java / etc');
}
