#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4825. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144737);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-24386", "CVE-2020-25275");
  script_xref(name:"DSA", value:"4825");

  script_name(english:"Debian DSA-4825-1 : dovecot - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the Dovecot email
server.

  - CVE-2020-24386
    When imap hibernation is active, an attacker (with valid
    credentials to access the mail server) can cause Dovecot
    to discover file system directory structures and access
    other users' emails via specially crafted commands.

  - CVE-2020-25275
    Innokentii Sennovskiy reported that the mail delivery
    and parsing in Dovecot can crash when the 10000th MIME
    part is message/rfc822 (or if the parent was
    multipart/digest). This flaw was introduced by earlier
    changes addressing CVE-2020-12100."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-24386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-25275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-12100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4825"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the dovecot packages.

For the stable distribution (buster), these problems have been fixed
in version 1:2.3.4.1-5+deb10u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24386");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/05");
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
if (deb_check(release:"10.0", prefix:"dovecot-auth-lua", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-core", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-dev", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-gssapi", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-imapd", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-ldap", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-lmtpd", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-lucene", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-managesieved", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-mysql", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-pgsql", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-pop3d", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-sieve", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-solr", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-sqlite", reference:"1:2.3.4.1-5+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-submissiond", reference:"1:2.3.4.1-5+deb10u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
