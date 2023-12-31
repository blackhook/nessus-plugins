#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1164. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22706);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4434");
  script_bugtraq_id(19714);
  script_xref(name:"DSA", value:"1164");

  script_name(english:"Debian DSA-1164-1 : sendmail - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A programming error has been discovered in sendmail, an alternative
mail transport agent for Debian, that could allow a remote attacker to
crash the sendmail process by sending a specially crafted email
message.

Please note that in order to install this update you also need
libsasl2 library from proposed updates as outlined in DSA 1155-2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=385054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1164"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sendmail package.

For the stable distribution (sarge) this problem has been fixed in
version 8.13.3-3sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libmilter-dev", reference:"8.13.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libmilter0", reference:"8.13.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"rmail", reference:"8.13.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail", reference:"8.13.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail-base", reference:"8.13.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail-bin", reference:"8.13.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail-cf", reference:"8.13.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"sendmail-doc", reference:"8.13.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"sensible-mda", reference:"8.13.4-3sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
