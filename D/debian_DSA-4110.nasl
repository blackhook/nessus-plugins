#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4110. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106728);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-6789");
  script_xref(name:"DSA", value:"4110");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"Debian DSA-4110-1 : exim4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Meh Chang discovered a buffer overflow flaw in a utility function used
in the SMTP listener of Exim, a mail transport agent. A remote
attacker can take advantage of this flaw to cause a denial of service,
or potentially the execution of arbitrary code via a specially crafted
message."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=890000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4110"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the exim4 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 4.84.2-2+deb8u5.

For the stable distribution (stretch), this problem has been fixed in
version 4.89-2+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"exim4", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-base", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-config", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-daemon-heavy", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-daemon-light", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-daemon-light-dbg", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-dbg", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"exim4-dev", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"eximon4", reference:"4.84.2-2+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"exim4", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-base", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-config", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-heavy", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-light", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-light-dbg", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-dbg", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-dev", reference:"4.89-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"eximon4", reference:"4.89-2+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");