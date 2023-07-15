#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2461-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143193);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/25");

  script_cve_id("CVE-2016-10742", "CVE-2020-11800");

  script_name(english:"Debian DLA-2461-1 : zabbix security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities were discovered in Zabbix, a network
monitoring solution. An attacker may remotely execute code on the
zabbix server, and redirect to external links through the zabbix web
frontend.

CVE-2016-10742

Zabbix allows open redirect via the request parameter.

CVE-2020-11800

Zabbix allows remote attackers to execute arbitrary code.

This update also includes several other bug fixes and improvements.
For more information please refer to the upstream changelog file.

For Debian 9 stretch, these problems have been fixed in version
1:3.0.31+dfsg-0+deb9u1.

We recommend that you upgrade your zabbix packages.

For the detailed security status of zabbix please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/zabbix

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/zabbix"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/zabbix"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11800");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-frontend-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-java-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-server-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"zabbix-agent", reference:"1:3.0.31+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"zabbix-frontend-php", reference:"1:3.0.31+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"zabbix-java-gateway", reference:"1:3.0.31+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"zabbix-proxy-mysql", reference:"1:3.0.31+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"zabbix-proxy-pgsql", reference:"1:3.0.31+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"zabbix-proxy-sqlite3", reference:"1:3.0.31+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"zabbix-server-mysql", reference:"1:3.0.31+dfsg-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"zabbix-server-pgsql", reference:"1:3.0.31+dfsg-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
