#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1275-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106723);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-6758");

  script_name(english:"Debian DLA-1275-1 : uwsgi security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the uwsgi_expand_path function in utils.c in
Unbit uWSGI, an application container server, has a stack-based buffer
overflow via a large directory length that can cause a
denial of service (application crash) or stack corruption.

For Debian 7 'Wheezy', these problems have been fixed in version
1.2.3+dfsg-5+deb7u2.

We recommend that you upgrade your uwsgi packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/02/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/uwsgi"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-ruwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-ruwsgi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-uwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-uwsgi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-uwsgi-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-uwsgicc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-uwsgidecorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-uwsgidecorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-app-integration-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-infrastructure-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-carbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-echo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-erlang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-fastrouter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-fiber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-graylog2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-greenlet-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-jvm-openjdk-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-jwsgi-openjdk-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-logsocket");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-lua5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-probeconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-probepg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-psgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-pyerl-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-pyerl-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-rack-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-rack-ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-rpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-signal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-symcall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugin-ugreen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uwsgi-plugins-all");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-ruwsgi", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-ruwsgi-dbg", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-uwsgi", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-uwsgi-dbg", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-django-uwsgi-admin", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-uwsgicc", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-uwsgidecorators", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python3-uwsgidecorators", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-app-integration-plugins", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-core", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-dbg", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-extra", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-infrastructure-plugins", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-admin", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-cache", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-carbon", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-cgi", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-echo", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-erlang", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-fastrouter", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-fiber", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-graylog2", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-greenlet-python", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-http", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-jvm-openjdk-6", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-jwsgi-openjdk-6", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-logsocket", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-lua5.1", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-nagios", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-ping", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-probeconnect", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-probepg", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-psgi", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-pyerl-python", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-pyerl-python3", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-python", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-python3", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-rack-ruby1.8", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-rack-ruby1.9.1", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-rpc", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-rrdtool", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-rsyslog", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-signal", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-symcall", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-syslog", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugin-ugreen", reference:"1.2.3+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"uwsgi-plugins-all", reference:"1.2.3+dfsg-5+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
