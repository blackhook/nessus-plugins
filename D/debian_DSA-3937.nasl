#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3937. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102444);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-2824", "CVE-2017-2825");
  script_xref(name:"DSA", value:"3937");

  script_name(english:"Debian DSA-3937-1 : zabbix - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Lilith Wyatt discovered two vulnerabilities in the Zabbix network
monitoring system which may result in execution of arbitrary code or
database writes by malicious proxies."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/zabbix"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3937"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the zabbix packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1:2.2.7+dfsg-2+deb8u3.

For the stable distribution (stretch), these problems have been fixed
prior to the initial release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"zabbix-agent", reference:"1:2.2.7+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-frontend-php", reference:"1:2.2.7+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-java-gateway", reference:"1:2.2.7+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-proxy-mysql", reference:"1:2.2.7+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-proxy-pgsql", reference:"1:2.2.7+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-proxy-sqlite3", reference:"1:2.2.7+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-server-mysql", reference:"1:2.2.7+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"zabbix-server-pgsql", reference:"1:2.2.7+dfsg-2+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
