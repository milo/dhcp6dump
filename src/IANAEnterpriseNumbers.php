<?php declare(strict_types=1);

namespace Milo\Net;


/**
 * @see https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
 */
class IANAEnterpriseNumbers
{
	const
		CISCO_SYSTEMS = 9,
		HEWLETT_PACKARD = 11,
		MICROSOFT = 311,
		JUNIPER_NETWORKS = 1411,
		DHCPD_PROJECT = 40712,
		SYSTEMD = 43793;

	private static $vendors = [
		self::CISCO_SYSTEMS => 'Cisco Systems',
		self::HEWLETT_PACKARD => 'Hewlett-Packard',
		self::MICROSOFT => 'Microsoft',
		self::JUNIPER_NETWORKS => 'Juniper Networks',
		self::DHCPD_PROJECT => 'DHCPCD Project',
		self::SYSTEMD => 'systemd',
	];


	public static function getVendor(int $id, string $notFound = '?'): string
	{
		return self::$vendors[$id] ?? $notFound;
	}
}
