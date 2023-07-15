#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2362-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140224);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2020-11984");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DLA-2362-1 : uwsgi security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Apache HTTP Server versions before 2.4.32 uses src:uwsgi where a flaw
was discovered. The uwsgi protocol does not let us serialize more than
16K of HTTP header leading to resource exhaustion and denial of
service.

For Debian 9 stretch, this problem has been fixed in version
2.0.14+20161117-3+deb9u3.

We recommend that you upgrade your uwsgi packages.

For the detailed security status of uwsgi please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/uwsgi

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/uwsgi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/uwsgi"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-proxy-uwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-proxy-uwsgi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-ruwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-ruwsgi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-uwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-uwsgi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-uwsgidecorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-uwsgidecorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-app-integration-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-emperor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-infrastructure-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-mongodb-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-alarm-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-alarm-xmpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-asyncio-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-asyncio-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-curl-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-emperor-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-fiber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-gccgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-gevent-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-graylog2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-greenlet-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-jvm-openjdk-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-jwsgi-openjdk-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-lua5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-lua5.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-luajit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-psgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-rack-ruby2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-rbthreads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-ring-openjdk-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-router-access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-servlet-openjdk-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-tornado-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-v8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-xslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugins-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libapache2-mod-proxy-uwsgi", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-proxy-uwsgi-dbg", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-ruwsgi", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-ruwsgi-dbg", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-uwsgi", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-uwsgi-dbg", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python-uwsgidecorators", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python3-uwsgidecorators", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-app-integration-plugins", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-core", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-dbg", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-emperor", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-extra", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-infrastructure-plugins", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-mongodb-plugins", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-alarm-curl", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-alarm-xmpp", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-asyncio-python", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-asyncio-python3", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-curl-cron", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-emperor-pg", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-fiber", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-gccgo", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-geoip", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-gevent-python", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-glusterfs", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-graylog2", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-greenlet-python", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-jvm-openjdk-8", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-jwsgi-openjdk-8", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-ldap", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-lua5.1", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-lua5.2", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-luajit", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-mono", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-php", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-psgi", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-python", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-python3", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-rack-ruby2.3", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-rados", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-rbthreads", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-ring-openjdk-8", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-router-access", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-servlet-openjdk-8", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-sqlite3", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-tornado-python", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-v8", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugin-xslt", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-plugins-all", reference:"2.0.14+20161117-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"uwsgi-src", reference:"2.0.14+20161117-3+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
