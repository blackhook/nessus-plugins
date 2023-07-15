#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4130. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107122);
  script_version("3.4");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-14461", "CVE-2017-15130", "CVE-2017-15132");
  script_xref(name:"DSA", value:"4130");

  script_name(english:"Debian DSA-4130-1 : dovecot - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Dovecot email
server. The Common Vulnerabilities and Exposures project identifies
the following issues :

  - CVE-2017-14461
    Aleksandar Nikolic of Cisco Talos and 'flxflndy'
    discovered that Dovecot does not properly parse invalid
    email addresses, which may cause a crash or leak memory
    contents to an attacker.

  - CVE-2017-15130
    It was discovered that TLS SNI config lookups may lead
    to excessive memory usage, causing imap-login/pop3-login
    VSZ limit to be reached and the process restarted,
    resulting in a denial of service. Only Dovecot
    configurations containing local_name { } or local { }
    configuration blocks are affected.

  - CVE-2017-15132
    It was discovered that Dovecot contains a memory leak
    flaw in the login process on aborted SASL
    authentication."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=888432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-14461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-15132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4130"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dovecot packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1:2.2.13-12~deb8u4.

For the stable distribution (stretch), these problems have been fixed
in version 1:2.2.27-3+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"dovecot-core", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-dbg", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-dev", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-gssapi", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-imapd", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-ldap", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-lmtpd", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-lucene", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-managesieved", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-mysql", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-pgsql", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-pop3d", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-sieve", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-solr", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-sqlite", reference:"1:2.2.13-12~deb8u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-core", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-dbg", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-dev", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-gssapi", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-imapd", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-ldap", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-lmtpd", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-lucene", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-managesieved", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-mysql", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-pgsql", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-pop3d", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-sieve", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-solr", reference:"1:2.2.27-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-sqlite", reference:"1:2.2.27-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
