#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4590. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132326);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2019-19783");
  script_xref(name:"DSA", value:"4590");

  script_name(english:"Debian DSA-4590-1 : cyrus-imapd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the lmtpd component of the Cyrus IMAP server
created mailboxes with administrator privileges if the 'fileinto' was
used, bypassing ACL checks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/cyrus-imapd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/cyrus-imapd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/cyrus-imapd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4590"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cyrus-imapd packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 2.5.10-3+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 3.0.8-6+deb10u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19783");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"cyrus-admin", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-caldav", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-clients", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-common", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-dev", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-doc", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-imapd", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-murder", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-nntpd", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-pop3d", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"cyrus-replication", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"libcyrus-imap-perl", reference:"3.0.8-6+deb10u3")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-admin", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-caldav", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-clients", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-common", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-dev", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-doc", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-imapd", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-murder", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-nntpd", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-pop3d", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"cyrus-replication", reference:"2.5.10-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libcyrus-imap-perl", reference:"2.5.10-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
