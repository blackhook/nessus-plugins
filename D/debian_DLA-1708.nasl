#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1708-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122762);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-10742", "CVE-2017-2826");

  script_name(english:"Debian DLA-1708-1 : zabbix security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were discovered in Zabbix, a
server/client network monitoring solution.

CVE-2016-10742

Zabbix allowed remote attackers to redirect to external links by
misusing the request parameter.

CVE-2017-2826

An information disclosure vulnerability exists in the iConfig proxy
request of Zabbix server. A specially crafted iConfig proxy request
can cause the Zabbix server to send the configuration information of
any Zabbix proxy, resulting in information disclosure. An attacker can
make requests from an active Zabbix proxy to trigger this
vulnerability.

This update also includes several other bug fixes and improvements.
For more information please refer to the upstream changelog file.

For Debian 8 'Jessie', these problems have been fixed in version
1:2.2.23+dfsg-0+deb8u1.

We recommend that you upgrade your zabbix packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/zabbix"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"zabbix-agent", reference:"1:2.2.23+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-frontend-php", reference:"1:2.2.23+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-java-gateway", reference:"1:2.2.23+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-proxy-mysql", reference:"1:2.2.23+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-proxy-pgsql", reference:"1:2.2.23+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-proxy-sqlite3", reference:"1:2.2.23+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-server-mysql", reference:"1:2.2.23+dfsg-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-server-pgsql", reference:"1:2.2.23+dfsg-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
