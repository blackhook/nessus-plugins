#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4614. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133417);
  script_version("1.5");
  script_cvs_date("Date: 2020/02/13");

  script_cve_id("CVE-2019-18634");
  script_xref(name:"DSA", value:"4614");

  script_name(english:"Debian DSA-4614-1 : sudo - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joe Vennix discovered a stack-based buffer overflow vulnerability in
sudo, a program designed to provide limited super user privileges to
specific users, triggerable when configured with the 'pwfeedback'
option enabled. An unprivileged user can take advantage of this flaw
to obtain full root privileges.

Details can be found in the upstream advisory at
https://www.sudo.ws/alerts/pwfeedback.html ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=950371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.sudo.ws/alerts/pwfeedback.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/sudo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/sudo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4614"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sudo packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 1.8.19p1-2.1+deb9u2.

For the stable distribution (buster), exploitation of the bug is
prevented due to a change in EOF handling introduced in 1.8.26."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"sudo", reference:"1.8.19p1-2.1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"sudo-ldap", reference:"1.8.19p1-2.1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
