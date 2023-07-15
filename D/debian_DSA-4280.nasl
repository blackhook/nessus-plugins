#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4280. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112066);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-15473");
  script_xref(name:"DSA", value:"4280");

  script_name(english:"Debian DSA-4280-1 : openssh - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dariusz Tytko, Michal Sajdak and Qualys Security discovered that
OpenSSH, an implementation of the SSH protocol suite, was prone to a
user enumeration vulnerability. This would allow a remote attacker to
check whether a specific user account existed on the target server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=906236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4280"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssh packages.

For the stable distribution (stretch), this problem has been fixed in
version 1:7.4p1-10+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"openssh-client", reference:"1:7.4p1-10+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-client-ssh1", reference:"1:7.4p1-10+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-client-udeb", reference:"1:7.4p1-10+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-server", reference:"1:7.4p1-10+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-server-udeb", reference:"1:7.4p1-10+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-sftp-server", reference:"1:7.4p1-10+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"ssh", reference:"1:7.4p1-10+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"ssh-askpass-gnome", reference:"1:7.4p1-10+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"ssh-krb5", reference:"1:7.4p1-10+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
