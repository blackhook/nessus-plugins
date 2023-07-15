#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4905. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(149038);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/11");

  script_cve_id("CVE-2021-31826");
  script_xref(name:"DSA", value:"4905");

  script_name(english:"Debian DSA-4905-1 : shibboleth-sp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that the Shibboleth Service Provider is prone to a
NULL pointer dereference flaw in the cookie-based session recovery
feature. A remote, unauthenticated attacker can take advantage of this
flaw to cause a denial of service (crash in the shibd daemon/service).

For additional information please refer to the upstream advisory at
https://shibboleth.net/community/advisories/secadv_20210426.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=987608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://shibboleth.net/community/advisories/secadv_20210426.txt"
  );
  # https://security-tracker.debian.org/tracker/source-package/shibboleth-sp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82c1ec06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/shibboleth-sp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4905"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the shibboleth-sp packages.

For the stable distribution (buster), this problem has been fixed in
version 3.0.4+dfsg1-1+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31826");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:shibboleth-sp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libapache2-mod-shib", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libapache2-mod-shib2", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libshibsp-dev", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libshibsp-doc", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libshibsp-plugins", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libshibsp8", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"shibboleth-sp-common", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"shibboleth-sp-utils", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"shibboleth-sp2-common", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"shibboleth-sp2-utils", reference:"3.0.4+dfsg1-1+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
