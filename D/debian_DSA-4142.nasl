#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4142. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108419);
  script_version("1.10");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id("CVE-2018-7490");
  script_xref(name:"DSA", value:"4142");

  script_name(english:"Debian DSA-4142-1 : uwsgi - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marios Nicolaides discovered that the PHP plugin in uWSGI, a fast,
self-healing application container server, does not properly handle a
DOCUMENT_ROOT check during use of the --php-docroot option, allowing a
remote attacker to mount a directory traversal attack and gain
unauthorized read access to sensitive files located outside of the web
root directory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/uwsgi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/uwsgi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/uwsgi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4142"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the uwsgi packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2.0.7-1+deb8u2. This update additionally includes the fix
for CVE-2018-6758 which was aimed to be addressed in the upcoming
jessie point release.

For the stable distribution (stretch), this problem has been fixed in
version 2.0.14+20161117-3+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"uWSGI Path Traversal File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"libapache2-mod-proxy-uwsgi", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-proxy-uwsgi-dbg", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-ruwsgi", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-ruwsgi-dbg", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-uwsgi", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-uwsgi-dbg", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-uwsgidecorators", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3-uwsgidecorators", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-app-integration-plugins", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-core", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-dbg", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-emperor", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-extra", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-infrastructure-plugins", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-alarm-curl", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-alarm-xmpp", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-curl-cron", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-emperor-pg", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-fiber", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-geoip", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-graylog2", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-greenlet-python", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-jvm-openjdk-7", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-jwsgi-openjdk-7", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-ldap", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-lua5.1", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-lua5.2", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-luajit", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-php", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-psgi", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-python", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-python3", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-rack-ruby2.1", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-rados", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-rbthreads", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-router-access", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-sqlite3", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-v8", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugin-xslt", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uwsgi-plugins-all", reference:"2.0.7-1+deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-proxy-uwsgi", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-proxy-uwsgi-dbg", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-ruwsgi", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-ruwsgi-dbg", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-uwsgi", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-uwsgi-dbg", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-uwsgidecorators", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3-uwsgidecorators", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-app-integration-plugins", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-core", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-dbg", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-emperor", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-extra", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-infrastructure-plugins", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-mongodb-plugins", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-alarm-curl", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-alarm-xmpp", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-asyncio-python", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-asyncio-python3", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-curl-cron", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-emperor-pg", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-fiber", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-gccgo", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-geoip", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-gevent-python", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-glusterfs", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-graylog2", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-greenlet-python", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-jvm-openjdk-8", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-jwsgi-openjdk-8", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-ldap", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-lua5.1", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-lua5.2", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-luajit", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-mono", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-php", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-psgi", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-python", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-python3", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-rack-ruby2.3", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-rados", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-rbthreads", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-ring-openjdk-8", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-router-access", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-servlet-openjdk-8", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-sqlite3", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-tornado-python", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-v8", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-xslt", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugins-all", reference:"2.0.14+20161117-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-src", reference:"2.0.14+20161117-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
