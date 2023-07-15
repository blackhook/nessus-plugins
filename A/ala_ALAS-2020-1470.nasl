##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020-12-23 due to Amazon pulling the previsouly published advisory.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1470.
##

include('compat.inc');

if (description)
{
  script_id(144468);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/23");

  script_cve_id(
    "CVE-2019-15691",
    "CVE-2019-15692",
    "CVE-2019-15693",
    "CVE-2019-15694",
    "CVE-2019-15695"
  );
  script_xref(name:"ALAS", value:"2020-1470");

  script_name(english:"Amazon Linux AMI : tigervnc (ALAS-2020-1470) (deprecated)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2020-1470 advisory.

  - TigerVNC version prior to 1.10.1 is vulnerable to stack use-after-return, which occurs due to incorrect
    usage of stack memory in ZRLEDecoder. If decoding routine would throw an exception, ZRLEDecoder may try to
    access stack variable, which has been already freed during the process of stack unwinding. Exploitation of
    this vulnerability could potentially result into remote code execution. This attack appear to be
    exploitable via network connectivity. (CVE-2019-15691)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow. Vulnerability could be triggered
    from CopyRectDecoder due to incorrect value checks. Exploitation of this vulnerability could potentially
    result into remote code execution. This attack appear to be exploitable via network connectivity.
    (CVE-2019-15692)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow, which occurs in
    TightDecoder::FilterGradient. Exploitation of this vulnerability could potentially result into remote code
    execution. This attack appear to be exploitable via network connectivity. (CVE-2019-15693)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow, which could be triggered from
    DecodeManager::decodeRect. Vulnerability occurs due to the signdness error in processing MemOutStream.
    Exploitation of this vulnerability could potentially result into remote code execution. This attack appear
    to be exploitable via network connectivity. (CVE-2019-15694)

  - TigerVNC version prior to 1.10.1 is vulnerable to stack buffer overflow, which could be triggered from
    CMsgReader::readSetCursor. This vulnerability occurs due to insufficient sanitization of PixelFormat.
    Since remote attacker can choose offset from start of the buffer to start writing his values, exploitation
    of this vulnerability could potentially result into remote code execution. This attack appear to be
    exploitable via network connectivity. (CVE-2019-15695)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated due to Amazon pulling the previously published advisory.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1470.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15691");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15692");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15693");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15694");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15695");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

exit(0, "This plugin has been deprecated due to Amazon pulling the previously published advisory.");
