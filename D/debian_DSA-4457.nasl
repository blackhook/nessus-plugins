#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4457. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125783);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/12 10:41:31");

  script_cve_id("CVE-2018-15587");
  script_xref(name:"DSA", value:"4457");

  script_name(english:"Debian DSA-4457-1 : evolution - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hanno Bock discovered that Evolution was vulnerable to OpenPGP
signatures being spoofed for arbitrary messages using a specially
crafted HTML email. This issue was mitigated by moving the security
bar with encryption and signature information above the message
headers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=924616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/evolution"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/evolution"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4457"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the evolution packages.

For the stable distribution (stretch), this problem has been fixed in
version 3.22.6-1+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/10");
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
if (deb_check(release:"9.0", prefix:"evolution", reference:"3.22.6-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"evolution-common", reference:"3.22.6-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"evolution-dev", reference:"3.22.6-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"evolution-plugins", reference:"3.22.6-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"evolution-plugins-experimental", reference:"3.22.6-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libevolution", reference:"3.22.6-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
