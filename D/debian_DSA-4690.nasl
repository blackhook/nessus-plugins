#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4690. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136754);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2020-10957", "CVE-2020-10958", "CVE-2020-10967");
  script_xref(name:"DSA", value:"4690");

  script_name(english:"Debian DSA-4690-1 : dovecot - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in the Dovecot email server,
which could cause crashes in the submission, submission-login or lmtp
services, resulting in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=960963"
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
    value:"https://www.debian.org/security/2020/dsa-4690"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the dovecot packages.

For the stable distribution (buster), these problems have been fixed
in version 1:2.3.4.1-5+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10967");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"dovecot-auth-lua", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-core", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-dev", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-gssapi", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-imapd", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-ldap", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-lmtpd", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-lucene", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-managesieved", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-mysql", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-pgsql", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-pop3d", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-sieve", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-solr", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-sqlite", reference:"1:2.3.4.1-5+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dovecot-submissiond", reference:"1:2.3.4.1-5+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
