#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3998. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103794);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-7805");
  script_xref(name:"DSA", value:"3998");

  script_name(english:"Debian DSA-3998-1 : nss - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Martin Thomson discovered that nss, the Mozilla Network Security
Service library, is prone to a use-after-free vulnerability in the TLS
1.2 implementation when handshake hashes are generated. A remote
attacker can take advantage of this flaw to cause an application using
the nss library to crash, resulting in a denial of service, or
potentially to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3998"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nss packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2:3.26-1+debu8u3.

For the stable distribution (stretch), this problem has been fixed in
version 2:3.26.2-1.1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");
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
if (deb_check(release:"8.0", prefix:"libnss3", reference:"2:3.26-1+debu8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-1d", reference:"2:3.26-1+debu8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-dbg", reference:"2:3.26-1+debu8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-dev", reference:"2:3.26-1+debu8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-tools", reference:"2:3.26-1+debu8u3")) flag++;
if (deb_check(release:"9.0", prefix:"libnss3", reference:"2:3.26.2-1.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libnss3-dbg", reference:"2:3.26.2-1.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libnss3-dev", reference:"2:3.26.2-1.1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libnss3-tools", reference:"2:3.26.2-1.1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");