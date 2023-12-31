#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90474);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118");

  script_name(english:"FreeBSD : samba -- multiple vulnerabilities (a636fc26-00d9-11e6-b704-000c292e4fd8) (Badlock)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba team reports :

[CVE-2015-5370] Errors in Samba DCE-RPC code can lead to denial of
service (crashes and high cpu consumption) and man in the middle
attacks.

[CVE-2016-2110] The feature negotiation of NTLMSSP is not downgrade
protected. A man in the middle is able to clear even required flags,
especially NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL.

[CVE-2016-2111] When Samba is configured as Domain Controller it
allows remote attackers to spoof the computer name of a secure
channel's endpoints, and obtain sensitive session information, by
running a crafted application and leveraging the ability to sniff
network traffic.

[CVE-2016-2112] A man in the middle is able to downgrade LDAP
connections to no integrity protection.

[CVE-2016-2113] Man in the middle attacks are possible for client
triggered LDAP connections (with ldaps://) and ncacn_http connections
(with https://).

[CVE-2016-2114] Due to a bug Samba doesn't enforce required smb
signing, even if explicitly configured.

[CVE-2016-2115] The protection of DCERPC communication over ncacn_np
(which is the default for most the file server related protocols) is
inherited from the underlying SMB connection.

[CVE-2016-2118] a.k.a. BADLOCK. A man in the middle can intercept any
DCERPC traffic between a client and a server in order to impersonate
the client and get the same privileges as the authenticated user
account. This is most problematic against active directory domain
controllers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2015-5370.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2111.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2112.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2114.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2016-2118.html"
  );
  # https://vuxml.freebsd.org/freebsd/a636fc26-00d9-11e6-b704-000c292e4fd8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5a3a7ed"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba42");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba44");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"samba36>=3.6.0<=3.6.25_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba4>=4.0.0<=4.0.26")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba41>=4.1.0<=4.1.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba42>=4.2.0<4.2.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba43>=4.3.0<4.3.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"samba44>=4.4.0<4.4.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
