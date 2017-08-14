<?php declare(strict_types=1);

namespace Milo\Net;

error_reporting(E_ALL);
ini_set('display_errors', '1');

require __DIR__ . '/src/StringReader.php';
require __DIR__ . '/src/DHCPv6Dumper.php';
require __DIR__ . '/src/DHCPv6Messages.php';
require __DIR__ . '/src/DHCPv6Options.php';
require __DIR__ . '/src/DHCPv6VendorOptions.php';
require __DIR__ . '/src/IANAEnterpriseNumbers.php';


define('DHCP6DUMPER_VERSION', '3');


function usage() {
	$tmp = \Phar::running() === ''
		? ('php ' . basename(__FILE__))
		: ('./' . basename(\Phar::running(false)));

	echo <<<HELP
Usage: tcpdump -nn -i eth0 -s 0 -U -w - port 546 or port 547 | $tmp

    -v    be verbose and always hex dump every message and option

    -V    show version
    -h    show this help

HELP;
}


$opts = getopt('vVh');
if (isset($opts['h'])) {
	usage();
	exit(0);

} elseif (isset($opts['V'])) {
	echo DHCP6DUMPER_VERSION . "\n";
	exit(0);
}

$input = defined('STDIN') ? STDIN : fopen('php://stdin', 'rb');
if (function_exists('posix_isatty') && posix_isatty($input)) {
	usage();
	exit(1);
}


# libpcap file format (https://wiki.wireshark.org/Development/LibpcapFileFormat):
#     Global Header | Packet Header | Packet Data | Packet Header | Packet Data | ...
#
#     Global Header is:
#         u32 magic number
#             0xa1b2c3d4 - native format
#             0xd4c3b2a1 - swapped, everything has to be swapped
#             0xa1b23c4d - native format, nanoseconds resolution
#             0x4d3cb2a1 - swappee, nanoseconds resolution
#
#         u16 major version
#         u16 minor version
#         s16 this zone - GMT to local correction
#         u32 sigfix - accuracy of timestamps
#         u32 snaplen - max length of captured packets, in octets
#         u32 network - data link type
switch (fread($input, 4)) {
	case "\xA1\xB2\xC3\xD4":
		$swapped = false;
		$nanoseconds = false;
		break;

	case "\xD4\xC3\xB2\xA1":
		$swapped = true;
		$nanoseconds = false;
		break;

	case "\xA1\xB2\x3C\x4D":
		$swapped = false;
		$nanoseconds = true;
		break;

	case "\x4D\x3C\xB2\xA1":
		$swapped = true;
		$nanoseconds = true;
		break;

	default:
		throw new \RuntimeException('Unknown input format.');
}

$globalHeader = (object) unpack($swapped
	? 'vmajor/vminor/Vzone/Vsigfix/Vsnaplen/Vnetwork'
	: 'nmajor/nminor/Nzone/Nsigfix/Nsnaplen/Nnetwork',
	fread($input, 20)
);

echo sprintf('# Input format: swapped=%s, nanoseconds=%s, version=%u.%u, zone=%u, sigfix=%d, snaplen=%u, network=%u',
	$swapped ? 'yes' : 'no',
	$nanoseconds ? 'yes' : 'no',
	$globalHeader->major,
	$globalHeader->minor,
	$globalHeader->zone,
	$globalHeader->sigfix,
	$globalHeader->snaplen,
	$globalHeader->network
) . "\n\n";

if ($globalHeader->network !== DHCPv6Dumper::HW_TYPE_ETHERNET) {
	throw new \RuntimeException("Unsupported data link type '$globalHeader->network'. Not sure what to do else.");
}


#     Packet Header is:
#         u32 ts_sec - timestamp seconds
#         u32 ts_usec - timestamp microseconds
#         u32 incl_len - number of octets of packet saved in file
#         u32 orig_len - actual length of packet
#
#     Packet Data follows every Packet Header and is incl_len long.
#
function packets($source, $swapped)
{
	while (($tmp = fread($source, 16)) !== '') {
		$header = (object) unpack($swapped
			? 'Vsec/Vusec/Vlength/VoriginalLength'
			: 'Nsec/Nusec/Nlength/NoriginalLength',
			$tmp
		);
		# TODO: skip or warning when length !== originalLength

		yield [$header, fread($source, $header->length)];
	};
}


$count = 0;
foreach (packets($input, $swapped) as list($header, $data)) {
	$count++;
	echo sprintf('No.%u (%s.%06u UTC)', $count, date('Y-m-d H:i:s', $header->sec), $header->usec) . "\n";  # TODO: Zone & sigfix correction
	echo "\n";
	(new DHCPv6Dumper($data, isset($opts['v'])))->dump();
	echo str_repeat('-', 80) . "\n";
}
