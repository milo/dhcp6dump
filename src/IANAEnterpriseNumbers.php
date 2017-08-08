<?php declare(strict_types=1);

namespace Milo\Net;


/**
 * @see https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
 */
class IANAEnterpriseNumbers
{
	const
		CISCO_SYSTEMS = 9,
		MICROSOFT = 311,
		JUNIPER_NETWORKS = 1411;

	private static $vendors = [
		self::CISCO_SYSTEMS => 'Cisco Systems',
		self::MICROSOFT => 'Microsoft',
		self::JUNIPER_NETWORKS => 'Juniper Networks',
	];


	public static function getVendor(int $id, string $notFound = '?'): string
	{
		return self::$vendors[$id] ?? $notFound;
	}
}
