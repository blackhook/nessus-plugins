#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4218. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110386);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2017-9951", "CVE-2018-1000115", "CVE-2018-1000127");
  script_xref(name:"DSA", value:"4218");

  script_name(english:"Debian DSA-4218-1 : memcached - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in memcached, a
high-performance memory object caching system. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2017-9951
    Daniel Shapira reported a heap-based buffer over-read in
    memcached (resulting from an incomplete fix for
    CVE-2016-8705 ) triggered by specially crafted requests
    to add/set a key and allowing a remote attacker to cause
    a denial of service.

  - CVE-2018-1000115
    It was reported that memcached listens to UDP by
    default. A remote attacker can take advantage of it to
    use the memcached service as a DDoS amplifier.

  Default installations of memcached in Debian are not affected by
  this issue as the installation defaults to listen only on localhost.
  This update disables the UDP port by default. Listening on the UDP
  can be re-enabled in the /etc/memcached.conf (cf.
  /usr/share/doc/memcached/NEWS.Debian.gz).

  - CVE-2018-1000127
    An integer overflow was reported in memcached, resulting
    in resource leaks, data corruption, deadlocks or
    crashes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=868701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=894404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1000115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-1000127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/memcached"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/memcached"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/memcached"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4218"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the memcached packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1.4.21-1.1+deb8u2.

For the stable distribution (stretch), these problems have been fixed
in version 1.4.33-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:memcached");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/07");
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
if (deb_check(release:"8.0", prefix:"memcached", reference:"1.4.21-1.1+deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"memcached", reference:"1.4.33-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
