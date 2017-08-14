<?php declare(strict_types=1);

namespace Milo\Net;


class DHCPv6Dumper
{
	const HW_TYPE_ETHERNET = 1;

	const ETH_TYPE_IPV6 = 0x86dd;

	const PACKET_VERSION_6 = 6;

	const PACKET_TYPE_UDP = 17;

	const SECONDS_TO_YEAR_2000 = 946684800;

	const
		DUID_LLT = 1,
		DUID_EN = 2,
		DUID_LL = 3,
		DUID_UUID = 4;

	private static $duidTypes = [
		self::DUID_LLT => 'DUID-LLT',
		self::DUID_EN => 'DUID-EN',
		self::DUID_LL => 'DUID-LL',
		self::DUID_UUID => 'DUID-UUID',
	];


	/** @var bool */
	public $beVerbose = false;

	/** @var StringReader */
	private $data;

	/** @var int */
	private $indent = 0;


	public function __construct(string $data)
	{
		$this->data = new StringReader($data);
	}


	public function dump(string $prefix = '')
	{
		ob_start();
		$this->out($prefix);

		# Ethernet Frame
		#     48b destination MAC
		#     48b source MAC
		#     16b frame type
		#
		$ethDstMac = self::decodeMac($this->data->read(6));
		$ethSrcMac = self::decodeMac($this->data->read(6));
		$ethFrameType = $this->unpack('n', $this->data->read(2));

		if ($ethFrameType !== self::ETH_TYPE_IPV6) {
			$this->notice('Ethernet frame is not type of IPv6.');
			$this->beVerbose ? ob_end_flush() : ob_end_clean();
			return;
		}

		$this->outf('Eth Src: %s', $ethSrcMac);
		$this->outf('Eth Dst: %s', $ethDstMac);
		$this->out('');


		# IPv6 packet
		#      32b
		#          4b protocol version
		#          8b traffic class
		#         20b flow label
		#      32b
		#         u16 payload length
		#          8b next header (same as for IPv4)
		#          8b hop limit - decremented every hop
		#     128b source address
		#     128b destination address
		#      ??b data
		#
		$ipv6 = $this->unpack('Nh1/nlength/CnextHeader/ChopLimit', $this->data->read(8));
		$ipv6Version = $ipv6->h1 >> 28;
		if ($ipv6Version !== self::PACKET_VERSION_6) {
			$this->notice('Packet is not version of 6.');
			$this->beVerbose ? ob_end_flush() : ob_end_clean();
			return;
		}

		if ($ipv6->nextHeader !== self::PACKET_TYPE_UDP) {
			$this->notice('Packet is not type of UDP.');
			$this->beVerbose ? ob_end_flush() : ob_end_clean();
			return;
		}

		$this->outf('IPv6 Src: %s', \inet_ntop($this->data->read(16)));
		$this->outf('IPv6 Dst: %s', \inet_ntop($this->data->read(16)));
		$this->out('');


		# UDP packet
		#     16b source port
		#     16b destination port
		#     16b UDP length
		#     16b checksum
		#     ??b data
		$udp = $this->unpack('nsrcPort/ndstPort/npayloadLength/nchecksum', $this->data->read(8));
		if (!in_array($udp->srcPort, [546, 547], true)) {
			$this->notice('UDP source port is not 546 or 547.');
			$this->beVerbose ? ob_end_flush() : ob_end_clean();
			return;
		}
		if (!in_array($udp->dstPort, [546, 547], true)) {
			$this->notice('UDP destination port is not 546 or 547.');
			$this->beVerbose ? ob_end_flush() : ob_end_clean();
			return;
		}

		$data = $this->data->read($udp->payloadLength - 8);  # 8B = UDP header length
		if ($this->beVerbose) {
			$this->out('Raw data:');
			$this->indent++;
			$this->hexDump($data);
			$this->indent--;
			$this->out('');
		}

		$this->dumpPacket(new StringReader($data));
		ob_end_flush();
	}


	private function dumpPacket(StringReader $data)
	{
		# DHCPv6 relay packet
		#       8b message type
		#       8b hop count
		#     128b link address
		#     128b peer address
		#      ??b options
		#
		# DHCPv6 non-relay packet
		#      8b message type
		#     24b transaction ID
		#     ??b options
		#
		$messageType = \ord($data->read(1));
		$this->outf('Message type: %u (%s)', $messageType, DHCPv6Messages::getName($messageType));
		$remain = $data->length - 1;

		if (in_array($messageType, [DHCPv6Messages::RELAY_FORWARD, DHCPv6Messages::RELAY_REPLY], true)) {
			$this->outf('Hop count: %u', \ord($data->read(1)));
			$remain -= 1;

			$this->outf('Link address: %s', \inet_ntop($data->read(16)));
			$this->outf('Peer address: %s', \inet_ntop($data->read(16)));
			$remain -= 32;

		} else {
			$tmp = $this->unpack('Ch/nl', $data->read(3));
			$remain -= 3;
			$this->outf('Transaction ID: 0x%06X', ($tmp->h << 16) | $tmp->l);
		}

		$this->dumpOptions($data, $remain);
	}


	private function dumpOptions(StringReader $data, int $dataLength)
	{
		while ($dataLength > 0) {
			$code = $this->unpack('n', $data->read(2));
			$length = $this->unpack('n', $data->read(2));
			$this->dumpOption($code, $data->read($length));
			$dataLength -= 4 + $length;
		}
	}


	private function dumpOption(int $code, string $data)
	{
		$this->outf('Option: %u (%s)', $code, DHCPv6Options::getName($code));
		$this->indent++;

		if ($this->beVerbose) {
			$this->out('Raw data:');
			$this->indent++;
			$this->hexDump($data);
			$this->indent--;
			$this->out('');
		}

		if (in_array($code, [DHCPv6Options::CLIENTID, DHCPv6Options::SERVERID, DHCPv6Options::RELAY_ID], true)) {
			$this->dumpDuid($data);

		} elseif ($code === DHCPv6Options::IA_NA) {
			$en = $this->unpack('Niaid/Nt1/Nt2', $data);
			$this->outf('IAID: %u', $en->iaid);
			$this->outf('T1: %us', $en->t1);
			$this->outf('T1: %us', $en->t2);
			if (\strlen($data) > 12) {
				$this->dumpOptions($tmp = new StringReader(\substr($data, 12)), $tmp->length);
			}

		} elseif ($code === DHCPv6Options::IAADDR) {
			$this->outf('Address: %s', inet_ntop(\substr($data, 0, 16)));
			$this->outf('Preferred life time: %us', $this->unpack('N', \substr($data, 16, 4)));
			$this->outf('Valid life time: %us', $this->unpack('N', \substr($data, 20, 4)));
			if (\strlen($data) > 24) {
				$this->out('TODO');
				$this->indent++;
				$this->hexDump(\substr($data, 24));
				$this->indent--;
			}

		} elseif ($code === DHCPv6Options::ORO) {
			foreach (\unpack('n*c', $data) as $c) {
				$this->outf('%2u (%s)', $c, DHCPv6Options::getName($c));
			}

		} elseif ($code === DHCPv6Options::PREFERENCE) {
			$this->outf('%u (0x%02X)', $pref = $this->unpack('C', $data), $pref);

		} elseif ($code === DHCPv6Options::ELAPSED_TIME) {
			$this->outf('%ums', $this->unpack('n', $data) * 10);

		} elseif ($code === DHCPv6Options::RELAY_MSG) {
			$this->indent++;
			$this->dumpPacket(new StringReader($data));
			$this->indent--;

		} elseif ($code === DHCPv6Options::STATUS_CODE) {
			static $statusCodes = [
				0 => 'Success',
				1 => 'Unspecified Failure',
				2 => 'No Addresses Available',
				3 => 'No Binding',
				4 => 'Not On Link',
				5 => 'Use Multicast',
			];

			$this->outf('Code: %u (%s)', $code = $this->unpack('n', \substr($data, 0, 2)), $statusCodes[$code] ?? '?');
			$this->outf('Message: %s', \substr($data, 2));

		} elseif ($code === DHCPv6Options::VENDOR_CLASS) {
			$this->outf('Enterprise Number: %u (%s)', $en = $this->unpack('N', \substr($data, 0, 4)), IANAEnterpriseNumbers::getVendor($en, 'TODO'));

			$len = \strlen($data);
			$pos = 4;
			$cnt = 0;
			while ($pos < $len) {
				$cnt++;
				$len = $this->unpack('n', \substr($data, $pos, 2));
				$pos += 2;
				$this->out("No.$cnt");
				$this->indent++;
				$this->hexDump(\substr($data, $pos, $len));
				$this->indent--;
				$pos += $len;
			}

		} elseif ($code === DHCPv6Options::VENDOR_OPTS) {
			$this->outf('Enterprise Number: %u (%s)', $en = $this->unpack('N', \substr($data, 0, 4)), IANAEnterpriseNumbers::getVendor($en, 'TODO'));
			$this->dumpVendorOptions($en, \substr($data, 4));

		} elseif ($code === DHCPv6Options::DNS_SERVERS) {
			foreach (str_split($data, 16) as $ip) {
				$this->out(\inet_ntop($ip));
			}

		} elseif ($code === DHCPv6Options::DOMAIN_LIST) {
			$this->out(self::decodeDomain($data));

		} elseif ($code === DHCPv6Options::INFORMATION_REFRESH_TIME) {
			$this->outf('%us', $this->unpack('N', $data));

		} elseif ($code === DHCPv6Options::CLIENT_FQDN) {
			$this->out('Flags: SON');
			$this->outf('       %08b', \ord(\substr($data, 0, 1)));
			$this->outf('Host: %s', self::decodeDomain(\substr($data, 1)));

		} else {
			$this->out('TODO');
			if (!$this->beVerbose) {
				$this->hexDump($data);
			}
		}

		$this->indent--;
		$this->out('');
	}


	private function dumpDuid(string $data)
	{
		$data = new StringReader($data);
		$type = $this->unpack('n', $data->read(2));

		$tmp = self::$duidTypes[$type] ?? null;
		$this->outf('Type: %u%s', $type, $tmp ? " ($tmp)" : '');

		$this->indent++;
		if ($type === self::DUID_LLT) {
			$tmp = $this->unpack('nhwType/Ntime', $data->read(6));
			$this->outf('Time: %s', date('Y-m-d H:i:s \G\M\T', self::SECONDS_TO_YEAR_2000 + $tmp->time));
			$this->outf('HW Type: %u%s', $tmp->hwType, $tmp->hwType === self::HW_TYPE_ETHERNET ? ' (ethernet)' : '');

			if ($tmp->hwType === self::HW_TYPE_ETHERNET) {
				$this->outf('MAC: %s', self::decodeMac($data->readRest()));
			} else {
				$this->hexDump($data->readRest());
			}

		} elseif ($type === self::DUID_EN) {
			$this->outf('Enterprise Number: %u (%s)', $en = $this->unpack('N', $data->read(8)), IANAEnterpriseNumbers::getVendor($en, 'TODO'));
			$this->hexDump($data->readRest());

		} elseif ($type === self::DUID_LL) {
			$hwType = $this->unpack('n', $data->read(2));
			$this->outf('HW Type: %u%s', $hwType, $hwType === self::HW_TYPE_ETHERNET ? ' (ethernet)' : '');
			if ($hwType === self::HW_TYPE_ETHERNET) {
				$this->outf('MAC: %s', self::decodeMac($data->readRest()));
			} else {
				$this->hexDump($data->readRest());
			}

		} elseif ($type === self::DUID_UUID) {
			$tmp = unpack('Na/nb/nc/nd/Ne/nf', $data->readRest());
			$this->outf('%08x-%04x-%04x-%04x-%08x%04x', ...array_values($tmp));

		} else {
			$this->hexDump($data->readRest());
		}
		$this->indent--;
	}


	private function dumpVendorOptions(int $vendor, string $data)
	{
		$len = \strlen($data);
		$pos = 0;
		while ($pos < $len) {
			$option = $this->unpack('ncode/nlength', \substr($data, $pos, 4));
			$pos += 4;
			$raw = \substr($data, $pos, $option->length);
			$pos += $option->length;
			$this->outf('Vendor Option: %u (%s)', $option->code, DHCPv6VendorOptions::getName($vendor, $option->code));
			$this->indent++;

			if ($vendor === IANAEnterpriseNumbers::CISCO_SYSTEMS && $option->code === DHCPv6VendorOptions::CISCO_SYSTEMS_TFTP) {
				foreach (str_split($raw, 16) as $ip) {
					$this->out(\inet_ntop($ip));
				}
			} else {
				$this->hexDump($raw);
			}

			$this->indent--;
		}
	}


	private function hexDump(string $s)
	{
		static $chunkLen = 16;

		$chunks = \str_split($s, $chunkLen);
		$lineCount = \count($chunks);
		foreach ($chunks as $chunk) {
			$tmp = [];
			$txt = '';
			foreach (\str_split($chunk) as $char) {
				$tmp[] = \sprintf('%02X', $ord = \ord($char));
				$txt .= ($ord > 0x20 && $ord < 0x7E) ? $char : '.';
			}
			$out = \implode(' ', $tmp);

			for ($i = \count($tmp); $lineCount > 1 && $i < $chunkLen; $i++) {
				$out .= '   ';
				$txt .= ' ';
			}

			$this->outf('%s  (%s)', $out, $txt);
		}
	}


	private function notice(string $message)
	{
		$this->out("NOTICE: $message");
	}


	private function out(string $line)
	{
		echo \str_repeat('    ', $this->indent) . $line . "\n";
	}


	private function outf(string $format, ...$args)
	{
		$this->out(\sprintf($format, ...$args));
	}


	/**
	 * @return int|\stdClass
	 */
	private function unpack(string $format, string $data)
	{
		if (\strlen($format) === 1) {
			return \unpack($format . 'x', $data)['x'];
		}

		return (object) \unpack($format, $data);
	}


	private static function decodeMac(string $s): string
	{
		return \implode(':', array_map(function ($ch) {
			return \sprintf('%02x', \ord($ch));
		}, str_split($s)));
	}


	private static function decodeDomain(string $s): string
	{
		$labels = [];
		$pos = 0;
		$length = \strlen($s) - 1;  # ends by 0x00
		while ($pos < $length) {
			$len = \ord(\substr($s, $pos, 1));
			$pos += 1;

			$labels[] = \substr($s, $pos, $len);
			$pos += $len;
		}
		return implode('.', $labels);
	}
}
