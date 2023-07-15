#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4357. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119850);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2018-11759");
  script_xref(name:"DSA", value:"4357");

  script_name(english:"Debian DSA-4357-1 : libapache-mod-jk - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Raphael Arrouas and Jean Lejeune discovered an access control bypass
vulnerability in mod_jk, the Apache connector for the Tomcat Java
servlet engine. The vulnerability is addressed by upgrading mod_jk to
the new upstream version 1.2.46, which includes additional changes.

  -
    https://tomcat.apache.org/connectors-doc/miscellaneous/c
    hangelog.html#Changes_between_1.2.42_and_1.2.43
  -
    https://tomcat.apache.org/connectors-doc/miscellaneous/c
    hangelog.html#Changes_between_1.2.43_and_1.2.44

  -
    https://tomcat.apache.org/connectors-doc/miscellaneous/c
    hangelog.html#Changes_between_1.2.44_and_1.2.45

  -
    https://tomcat.apache.org/connectors-doc/miscellaneous/c
    hangelog.html#Changes_between_1.2.45_and_1.2.46"
  );
  # https://tomcat.apache.org/connectors-doc/miscellaneous/changelog.html#Changes_between_1.2.42_and_1.2.43
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13abf0c5"
  );
  # https://tomcat.apache.org/connectors-doc/miscellaneous/changelog.html#Changes_between_1.2.43_and_1.2.44
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edeba873"
  );
  # https://tomcat.apache.org/connectors-doc/miscellaneous/changelog.html#Changes_between_1.2.44_and_1.2.45
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35e6cbe4"
  );
  # https://tomcat.apache.org/connectors-doc/miscellaneous/changelog.html#Changes_between_1.2.45_and_1.2.46
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e79ddc0"
  );
  # https://security-tracker.debian.org/tracker/source-package/libapache-mod-jk
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf94d944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libapache-mod-jk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4357"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libapache-mod-jk packages.

For the stable distribution (stretch), this problem has been fixed in
version 1:1.2.46-0+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache-mod-jk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libapache-mod-jk-doc", reference:"1:1.2.46-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-jk", reference:"1:1.2.46-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
