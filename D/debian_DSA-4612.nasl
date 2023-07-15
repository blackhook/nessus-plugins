#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4612. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133415);
  script_version("1.3");
  script_cvs_date("Date: 2020/02/06");

  script_cve_id("CVE-2020-8086");
  script_xref(name:"DSA", value:"4612");

  script_name(english:"Debian DSA-4612-1 : prosody-modules - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the LDAP authentication modules for the Prosody
Jabber/XMPP server incorrectly validated the XMPP address when
checking whether a user has admin access."
  );
  # https://security-tracker.debian.org/tracker/source-package/prosody-modules
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98030852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4612"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the prosody-modules packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 0.0~hg20170123.3ed504b944e5+dfsg-1+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 0.0~hg20190203.b54e98d5c4a1+dfsg-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8086");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:prosody-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/31");
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
if (deb_check(release:"10.0", prefix:"prosody-modules", reference:"0.0~hg20190203.b54e98d5c4a1+dfsg-1+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"prosody-modules", reference:"0.0~hg20170123.3ed504b944e5+dfsg-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
