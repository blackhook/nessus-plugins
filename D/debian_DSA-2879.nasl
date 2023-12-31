#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2879. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72994);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-0017");
  script_bugtraq_id(63445, 63888, 63890, 63931, 63983, 64111, 65963);
  script_xref(name:"DSA", value:"2879");

  script_name(english:"Debian DSA-2879-1 : libssh - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that libssh, a tiny C SSH library, did not reset the
state of the PRNG after accepting a connection. A server mode
application that forks itself to handle incoming connections could see
its children sharing the same PRNG state, resulting in a cryptographic
weakness and possibly the recovery of the private key."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-2879"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libssh packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 0.4.5-3+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 0.5.4-1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"libssh-4", reference:"0.4.5-3+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libssh-dbg", reference:"0.4.5-3+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libssh-dev", reference:"0.4.5-3+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libssh-doc", reference:"0.4.5-3+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"libssh-4", reference:"0.5.4-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libssh-dbg", reference:"0.5.4-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libssh-dev", reference:"0.5.4-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libssh-doc", reference:"0.5.4-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
