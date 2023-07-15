#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
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

include('compat.inc');

if (description)
{
  script_id(177844);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2023-22325",
    "CVE-2023-27395",
    "CVE-2023-27516",
    "CVE-2023-31192",
    "CVE-2023-32275",
    "CVE-2023-32634"
  );

  script_name(english:"FreeBSD : SoftEtherVPN -- multiple vulnerabilities (d821956f-1753-11ee-ad66-1c61b4739ac9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the d821956f-1753-11ee-ad66-1c61b4739ac9 advisory.

  - Daiyuu Nobori reports: The SoftEther VPN project received a high level code review and technical
    assistance from Cisco Systems, Inc. of the United States from April to June 2023 to fix several
    vulnerabilities in the SoftEther VPN code. The risk of exploitation of any of the fixed vulnerabilities is
    low under normal usage and environment, and actual attacks are very difficult. However, SoftEther VPN is
    now an open source VPN software used by 7.4 million unique users worldwide, and is used daily by many
    users to defend against the risk of blocking attacks by national censorship firewalls and attempts to
    eavesdrop on communications. Therefore, as long as the slightest attack possibility exists, there is great
    value in preventing vulnerabilities as much as possible in anticipation of the most sophisticated cyber
    attackers in the world, such as malicious ISPs and man-in-the-middle attackers on national Internet
    communication channels. These fixes are important and useful patches for users who use SoftEther VPN and
    the Internet for secure communications to prevent advanced attacks that can theoretically be triggered by
    malicious ISPs and man-in-the-middle attackers on national Internet communication pathways. The fixed
    vulnerabilities are CVE-2023-27395, CVE-2023-22325, CVE-2023-32275, CVE-2023-27516, CVE-2023-32634, and
    CVE-2023-31192. All of these were discovered in an outstanding code review of SoftEther VPN by Cisco
    Systems, Inc. (CVE-2023-22325, CVE-2023-27395, CVE-2023-27516, CVE-2023-31192, CVE-2023-32275,
    CVE-2023-32634)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.softether.org/9-about/News/904-SEVPN202301");
  # https://vuxml.freebsd.org/freebsd/d821956f-1753-11ee-ad66-1c61b4739ac9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2f86d38");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32634");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:softether");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:softether-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'softether-devel<4.42.9798',
    'softether<4.42.9798'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
