#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4986. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154177);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/15");

  script_cve_id("CVE-2021-30640", "CVE-2021-41079");

  script_name(english:"Debian DSA-4986-1 : tomcat9 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4986 advisory.

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

  - Apache Tomcat 8.5.0 to 8.5.63, 9.0.0-M1 to 9.0.43 and 10.0.0-M1 to 10.0.2 did not properly validate
    incoming TLS packets. When Tomcat was configured to use NIO+OpenSSL or NIO2+OpenSSL for TLS, a specially
    crafted packet could be used to trigger an infinite loop resulting in a denial of service.
    (CVE-2021-41079)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tomcat9");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4986");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41079");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/tomcat9");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/tomcat9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the tomcat9 packages.

For the stable distribution (bullseye), these problems have been fixed in version 9.0.43-2~deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat9-embed-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat9-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libtomcat9-embed-java', 'reference': '9.0.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'libtomcat9-java', 'reference': '9.0.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'tomcat9', 'reference': '9.0.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'tomcat9-admin', 'reference': '9.0.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'tomcat9-common', 'reference': '9.0.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'tomcat9-docs', 'reference': '9.0.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'tomcat9-examples', 'reference': '9.0.31-1~deb10u6'},
    {'release': '10.0', 'prefix': 'tomcat9-user', 'reference': '9.0.31-1~deb10u6'},
    {'release': '11.0', 'prefix': 'libtomcat9-embed-java', 'reference': '9.0.43-2~deb11u2'},
    {'release': '11.0', 'prefix': 'libtomcat9-java', 'reference': '9.0.43-2~deb11u2'},
    {'release': '11.0', 'prefix': 'tomcat9', 'reference': '9.0.43-2~deb11u2'},
    {'release': '11.0', 'prefix': 'tomcat9-admin', 'reference': '9.0.43-2~deb11u2'},
    {'release': '11.0', 'prefix': 'tomcat9-common', 'reference': '9.0.43-2~deb11u2'},
    {'release': '11.0', 'prefix': 'tomcat9-docs', 'reference': '9.0.43-2~deb11u2'},
    {'release': '11.0', 'prefix': 'tomcat9-examples', 'reference': '9.0.43-2~deb11u2'},
    {'release': '11.0', 'prefix': 'tomcat9-user', 'reference': '9.0.43-2~deb11u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
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
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtomcat9-embed-java / libtomcat9-java / tomcat9 / tomcat9-admin / etc');
}
