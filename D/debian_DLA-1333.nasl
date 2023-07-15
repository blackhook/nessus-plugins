#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1333-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108767);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-14461", "CVE-2017-15130", "CVE-2017-15132");

  script_name(english:"Debian DLA-1333-1 : dovecot security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Dovecot email
server. The Common Vulnerabilities and Exposures project identifies
the following issues :

CVE-2017-14461

Aleksandar Nikolic of Cisco Talos and 'flxflndy' discovered that
Dovecot does not properly parse invalid email addresses, which may
cause a crash or leak memory contents to an attacker.

CVE-2017-15130

It was discovered that TLS SNI config lookups may lead to excessive
memory usage, causing imap-login/pop3-login VSZ limit to be reached
and the process restarted, resulting in a denial of service. Only
Dovecot configurations containing local_name { } or local { }
configuration blocks are affected.

CVE-2017-15132

It was discovered that Dovecot contains a memory leak flaw in the
login process on aborted SASL authentication.

For Debian 7 'Wheezy', these problems have been fixed in version
1:2.1.7-7+deb7u2.

We recommend that you upgrade your dovecot packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dovecot"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lmtpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-managesieved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"dovecot-common", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-core", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-dbg", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-dev", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-gssapi", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-imapd", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-ldap", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-lmtpd", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-managesieved", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-mysql", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-pgsql", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-pop3d", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-sieve", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-solr", reference:"1:2.1.7-7+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"dovecot-sqlite", reference:"1:2.1.7-7+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
