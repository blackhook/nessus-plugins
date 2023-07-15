#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4239. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110911);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-1000528");
  script_xref(name:"DSA", value:"4239");

  script_name(english:"Debian DSA-4239-1 : gosa - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fabian Henneke discovered a cross-site scripting vulnerability in the
password change form of GOsa, a web-based LDAP administration program."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/gosa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/gosa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4239"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gosa packages.

For the stable distribution (stretch), this problem has been fixed in
version gosa 2.7.4+reloaded2-13+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gosa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/05");
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
if (deb_check(release:"9.0", prefix:"gosa", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-desktop", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-dev", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-help-de", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-help-en", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-help-fr", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-help-nl", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-connectivity", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-dhcp", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-dhcp-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-dns", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-dns-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-fai", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-fai-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-gofax", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-gofon", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-goto", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-kolab", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-kolab-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-ldapmanager", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-mail", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-mit-krb5", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-mit-krb5-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-nagios", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-nagios-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-netatalk", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-opengroupware", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-openxchange", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-openxchange-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-opsi", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-phpgw", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-phpgw-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-phpscheduleit", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-phpscheduleit-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-pptp", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-pptp-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-pureftpd", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-pureftpd-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-rolemanagement", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-rsyslog", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-samba", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-scalix", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-squid", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-ssh", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-ssh-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-sudo", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-sudo-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-systems", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-uw-imap", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-plugin-webdav", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gosa-schema", reference:"2.7.4+reloaded2-13+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
