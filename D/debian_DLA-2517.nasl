#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2517-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144758);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/14");

  script_cve_id("CVE-2020-24386", "CVE-2020-25275");

  script_name(english:"Debian DLA-2517-1 : dovecot security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that there were two issues in the Dovecot IMAP
server :

  - CVE-2020-24386: Prevent an issue where an attacker could
    cause Dovecot to discover file system directory
    structure and even access other users' emails using a
    pecially crafted command.

  - CVE-2020-25275: Prevent an issue where a malicious
    sender can crash Dovecot repeatedly by sending messages
    with more than 10,000 MIME parts.

For Debian 9 'Stretch', these problems has been fixed in version
1:2.2.27-3+deb9u7 and we recommend that you upgrade your dovecot
packages.

For the detailed security status of dovecot please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/dovecot

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/dovecot"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/dovecot"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24386");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lmtpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-managesieved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"dovecot-core", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-dbg", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-dev", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-gssapi", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-imapd", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-ldap", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-lmtpd", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-lucene", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-managesieved", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-mysql", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-pgsql", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-pop3d", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-sieve", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-solr", reference:"1:2.2.27-3+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-sqlite", reference:"1:2.2.27-3+deb9u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
