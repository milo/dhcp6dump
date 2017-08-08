<?php declare(strict_types=1);

namespace Milo\Net;


class DHCPv6VendorOptions
{
	const
		CISCO_SYSTEMS_TFTP = 1;

	private static $options = [
		IANAEnterpriseNumbers::CISCO_SYSTEMS => [
			self::CISCO_SYSTEMS_TFTP => 'TFTP',
		],
	];


	public static function getName(int $vendor, int $option, string $notFound = '?'): string
	{
		return self::$options[$vendor][$option] ?? $notFound;
	}
}
