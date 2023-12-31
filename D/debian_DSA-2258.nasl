#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2258. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55065);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1926");
  script_xref(name:"DSA", value:"2258");

  script_name(english:"Debian DSA-2258-1 : kolab-cyrus-imapd - implementation error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the STARTTLS implementation of the Kolab Cyrus
IMAP server does not properly restrict I/O buffering, which allows
man-in-the-middle attackers to insert commands into encrypted IMAP,
LMTP, NNTP and POP3 sessions by sending a cleartext command that is
processed after TLS is in place."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=629350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/kolab-cyrus-imapd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2258"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kolab-cyrus-imapd packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.2.13-5+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2.13-9.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kolab-cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"kolab-cyrus-imapd", reference:"2.2.13-5+lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"kolab-cyrus-admin", reference:"2.2.13-9.1")) flag++;
if (deb_check(release:"6.0", prefix:"kolab-cyrus-clients", reference:"2.2.13-9.1")) flag++;
if (deb_check(release:"6.0", prefix:"kolab-cyrus-common", reference:"2.2.13-9.1")) flag++;
if (deb_check(release:"6.0", prefix:"kolab-cyrus-imapd", reference:"2.2.13-9.1")) flag++;
if (deb_check(release:"6.0", prefix:"kolab-cyrus-pop3d", reference:"2.2.13-9.1")) flag++;
if (deb_check(release:"6.0", prefix:"kolab-libcyrus-imap-perl", reference:"2.2.13-9.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
